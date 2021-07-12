package cache

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/images/converter"
	"github.com/containerd/containerd/images/converter/uncompress"
	"github.com/containerd/containerd/labels"
	"github.com/containerd/stargz-snapshotter/estargz"
	estargzconv "github.com/containerd/stargz-snapshotter/nativeconverter/estargz"
	"github.com/moby/buildkit/util/compression"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

type descConvertFunc func(desc ocispec.Descriptor, info content.Info) *ocispec.Descriptor

// getConverters returns converter functions according to the specified compression type.
// If no conversion is needed, this returns nil without error.
func getConverters(desc ocispec.Descriptor, compressionType compression.Type) (converter.ConvertFunc, descConvertFunc, error) {
	switch compressionType {
	case compression.Uncompressed:
		if !images.IsLayerType(desc.MediaType) || uncompress.IsUncompressedType(desc.MediaType) {
			// No conversion. No need to return an error here.
			return nil, nil, nil
		}
		return uncompress.LayerConvertFunc, mediatypeConvertFunc(convertMediaTypeToUncompress), nil
	case compression.Gzip:
		if !images.IsLayerType(desc.MediaType) || isGzipCompressedType(desc.MediaType) {
			// No conversion. No need to return an error here.
			return nil, nil, nil
		}
		return gzipLayerConvertFunc, mediatypeConvertFunc(convertMediaTypeToGzip), nil
	case compression.EStargz:
		if !images.IsLayerType(desc.MediaType) {
			// No conversion. No need to return an error here.
			return nil, nil, nil
		}
		return eStargzLayerConvertFunc, eStargzDescConvertFunc, nil
	default:
		return nil, nil, fmt.Errorf("unknown compression type during conversion: %q", compressionType)
	}
}

func mediatypeConvertFunc(f func(string) string) descConvertFunc {
	return func(desc ocispec.Descriptor, info content.Info) *ocispec.Descriptor {
		newDesc := desc
		newDesc.MediaType = f(newDesc.MediaType)
		newDesc.Digest = info.Digest
		newDesc.Size = info.Size
		return &newDesc
	}
}

func gzipLayerConvertFunc(ctx context.Context, cs content.Store, desc ocispec.Descriptor) (*ocispec.Descriptor, error) {
	if !images.IsLayerType(desc.MediaType) || isGzipCompressedType(desc.MediaType) {
		// No conversion. No need to return an error here.
		return nil, nil
	}

	// prepare the source and destination
	info, err := cs.Info(ctx, desc.Digest)
	if err != nil {
		return nil, err
	}
	labelz := info.Labels
	if labelz == nil {
		labelz = make(map[string]string)
	}
	ra, err := cs.ReaderAt(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer ra.Close()
	ref := fmt.Sprintf("convert-gzip-from-%s", desc.Digest)
	w, err := cs.Writer(ctx, content.WithRef(ref))
	if err != nil {
		return nil, err
	}
	defer w.Close()
	if err := w.Truncate(0); err != nil { // Old written data possibly remains
		return nil, err
	}
	zw := gzip.NewWriter(w)
	defer zw.Close()

	// convert this layer
	diffID := digest.Canonical.Digester()
	if _, err := io.Copy(zw, io.TeeReader(io.NewSectionReader(ra, 0, ra.Size()), diffID.Hash())); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil { // Flush the writer
		return nil, err
	}
	labelz[labels.LabelUncompressed] = diffID.Digest().String() // update diffID label
	if err = w.Commit(ctx, 0, "", content.WithLabels(labelz)); err != nil && !errdefs.IsAlreadyExists(err) {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	info, err = cs.Info(ctx, w.Digest())
	if err != nil {
		return nil, err
	}

	newDesc := desc
	newDesc.MediaType = convertMediaTypeToGzip(newDesc.MediaType)
	newDesc.Digest = info.Digest
	newDesc.Size = info.Size
	return &newDesc, nil
}

func isGzipCompressedType(mt string) bool {
	switch mt {
	case
		images.MediaTypeDockerSchema2LayerGzip,
		images.MediaTypeDockerSchema2LayerForeignGzip,
		ocispec.MediaTypeImageLayerGzip,
		ocispec.MediaTypeImageLayerNonDistributableGzip:
		return true
	default:
		return false
	}
}

func convertMediaTypeToUncompress(mt string) string {
	switch mt {
	case images.MediaTypeDockerSchema2LayerGzip:
		return images.MediaTypeDockerSchema2Layer
	case images.MediaTypeDockerSchema2LayerForeignGzip:
		return images.MediaTypeDockerSchema2LayerForeign
	case ocispec.MediaTypeImageLayerGzip:
		return ocispec.MediaTypeImageLayer
	case ocispec.MediaTypeImageLayerNonDistributableGzip:
		return ocispec.MediaTypeImageLayerNonDistributable
	default:
		return mt
	}
}

func convertMediaTypeToGzip(mt string) string {
	if uncompress.IsUncompressedType(mt) {
		if images.IsDockerType(mt) {
			mt += ".gzip"
		} else {
			mt += "+gzip"
		}
		return mt
	}
	return mt
}

func eStargzLayerConvertFunc(ctx context.Context, cs content.Store, desc ocispec.Descriptor) (*ocispec.Descriptor, error) {
	newDesc, err := estargzconv.LayerConvertFunc()(ctx, cs, desc)
	if err != nil {
		return nil, err
	}
	return newDesc, saveEStargzAnnotations(ctx, cs, newDesc.Digest, newDesc.Annotations)
}

func eStargzDescConvertFunc(desc ocispec.Descriptor, info content.Info) *ocispec.Descriptor {
	newDesc := desc
	newDesc.MediaType = convertMediaTypeToGzip(newDesc.MediaType)
	newDesc.Digest = info.Digest
	newDesc.Size = info.Size
	newDesc.Annotations = mergeEStargzAnnotations(eStargzAnnotationsFromLabels(info.Labels), newDesc.Annotations)
	return &newDesc
}

// loadEStargzAnnotations loads eStargz annotations from the content store.
func loadEStargzAnnotations(ctx context.Context, cs content.Store, dgst digest.Digest) (map[string]string, error) {
	info, err := cs.Info(ctx, dgst)
	if err != nil {
		return nil, err
	}
	return eStargzAnnotationsFromLabels(info.Labels), nil
}

// saveEStargzAnnotaitons saves eStargz annotations to the content store
// as labels of the corresponding blob.
func saveEStargzAnnotations(ctx context.Context, cs content.Store, dgst digest.Digest, annotations map[string]string) error {
	saveAnnotations := mergeEStargzAnnotations(annotations, nil)
	if len(saveAnnotations) == 0 {
		return nil
	}
	info, err := cs.Info(ctx, dgst)
	if err != nil {
		return err
	}
	var fields []string
	info.Labels, fields = eStargzAnnotationsToLabels(saveAnnotations)
	_, err = cs.Update(ctx, info, fields...)
	return err
}

// writeEStargz writes the passed blobs stream as an eStargz-compressed blob.
// saveLabels function saves all necessary eStargz annotations to the content store.
func writeEStargz() (convert func(dest io.Writer, requiredMediaType string) (io.WriteCloser, error), mediaType string, saveLabels func(ctx context.Context, cs content.Store, dgst digest.Digest) error) {
	mediaType = ocispec.MediaTypeImageLayerGzip
	annotations := make(map[string]string)
	var mu sync.Mutex
	return func(dest io.Writer, requiredMediaType string) (io.WriteCloser, error) {
			if mediaType != requiredMediaType {
				return nil, fmt.Errorf("unsupported media type for estargz compressor %q", requiredMediaType)
			}
			done := make(chan struct{})
			c := new(counter)
			pr, pw := io.Pipe()
			go func() {
				defer close(done)
				defer pr.Close()
				w := estargz.NewWriter(dest)
				if err := w.AppendTar(io.TeeReader(pr, c)); err != nil {
					pr.CloseWithError(err)
					return
				}
				tocDgst, err := w.Close()
				if err != nil {
					pr.CloseWithError(err)
					return
				}
				mu.Lock()
				annotations[estargz.TOCJSONDigestAnnotation] = tocDgst.String()
				annotations[estargz.StoreUncompressedSizeAnnotation] = fmt.Sprintf("%d", c.size())
				mu.Unlock()
			}()
			return &writeCloser{pw, func() error {
				<-done // wait until the write completes
				return nil
			}}, nil
		}, mediaType, func(ctx context.Context, cs content.Store, dgst digest.Digest) error {
			mu.Lock()
			defer mu.Unlock()
			return saveEStargzAnnotations(ctx, cs, dgst, annotations)
		}
}

const eStargzAnnotationsLabelPrefix = "buildkit.io/compression/estargz/annotation."

func eStargzAnnotationsFromLabels(labels map[string]string) (annotations map[string]string) {
	for k, v := range labels {
		if strings.HasPrefix(k, eStargzAnnotationsLabelPrefix) {
			if annotations == nil {
				annotations = make(map[string]string)
			}
			annotations[strings.TrimPrefix(k, eStargzAnnotationsLabelPrefix)] = v
		}
	}
	return annotations
}

func eStargzAnnotationsToLabels(annotations map[string]string) (labels map[string]string, fields []string) {
	for k, v := range annotations {
		if labels == nil {
			labels = make(map[string]string)
		}
		k2 := eStargzAnnotationsLabelPrefix + k
		labels[k2] = v
		fields = append(fields, "labels."+k2)
	}
	return labels, fields
}

func mergeEStargzAnnotations(src, dst map[string]string) map[string]string {
	if src == nil {
		return dst
	}
	for _, k := range []string{estargz.TOCJSONDigestAnnotation, estargz.StoreUncompressedSizeAnnotation} {
		if v, ok := src[k]; ok {
			if dst == nil {
				dst = make(map[string]string)
			}
			dst[k] = v
		}
	}
	return dst
}

type writeCloser struct {
	io.WriteCloser
	closeFunc func() error
}

func (wc *writeCloser) Close() error {
	err1 := wc.WriteCloser.Close()
	err2 := wc.closeFunc()
	if err1 != nil {
		return errors.Wrapf(err1, "failed to close: %v", err2)
	}
	return err2
}

type counter struct {
	n  int64
	mu sync.Mutex
}

func (c *counter) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	c.n += int64(len(p))
	c.mu.Unlock()
	return len(p), nil
}

func (c *counter) size() (n int64) {
	c.mu.Lock()
	n = c.n
	c.mu.Unlock()
	return
}
