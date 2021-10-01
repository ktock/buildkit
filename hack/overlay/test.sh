#!/bin/bash

set -euo pipefail

CONTEXT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )/"
REPO="${CONTEXT}../../"

RESULT=${1}
IMAGE=${2}

if [ "${RESULT}" == "" ] || [ "${IMAGE}" == "" ] ; then
    echo "specify args: <result-file> <image>"
    exit 1
fi

TEST_ENV_IMAGE="testimage-$(date '+%Y%m%d%H%M%S')"
cat <<'EOF' | docker build -t "${TEST_ENV_IMAGE}" -f - "${REPO}"
ARG CONTAINERD_VERSION=v1.5.5
ARG RUNC_VERSION=v1.0.2
ARG CNI_PLUGINS_VERSION=v1.0.1

FROM golang:1.17-bullseye AS golang-base

FROM golang-base AS runc-dev
ARG RUNC_VERSION
RUN apt-get update -y && apt-get install -y libseccomp-dev && \
    git clone -b ${RUNC_VERSION} --depth 1 https://github.com/opencontainers/runc $GOPATH/src/github.com/opencontainers/runc && \
    cd $GOPATH/src/github.com/opencontainers/runc && \
    make && make install PREFIX=/out/

FROM golang-base AS containerd-dev
ARG CONTAINERD_VERSION
RUN apt-get update -y && apt-get install -y libbtrfs-dev && \
    git clone -b ${CONTAINERD_VERSION} --depth 1 https://github.com/containerd/containerd $GOPATH/src/github.com/containerd/containerd && \
    cd $GOPATH/src/github.com/containerd/containerd && \
    make && DESTDIR=/out/ PREFIX= make install

FROM golang-base AS buildkit-dev
COPY . $GOPATH/src/github.com/moby/buildkit
RUN cd $GOPATH/src/github.com/moby/buildkit && \
    mkdir /out/ && \
    go build -o /out/buildctl ./cmd/buildctl && \
    go build -ldflags "-w -extldflags -static" -tags "osusergo netgo static_build seccomp" -o /out/buildkitd ./cmd/buildkitd

FROM ubuntu:20.04
ARG CNI_PLUGINS_VERSION
ARG TARGETARCH
RUN apt-get update && apt-get install -y iptables curl && \
    update-alternatives --set iptables /usr/sbin/iptables-legacy && \
    mkdir -p /opt/cni/bin /etc/buildkit && \
    curl -Ls https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-${TARGETARCH:-amd64}-${CNI_PLUGINS_VERSION}.tgz | tar xzv -C /opt/cni/bin
COPY ./hack/fixtures/cni.json /etc/buildkit/cni.json
COPY --from=containerd-dev /out/bin/containerd /out/bin/containerd-shim-runc-v2 /out/bin/ctr /usr/local/bin/
COPY --from=runc-dev /out/sbin/* /usr/local/sbin/
COPY --from=buildkit-dev /out/* /usr/local/bin/
EOF


TEST_ENV_NAME="testenv-$(date '+%Y%m%d%H%M%S')"
docker run --privileged --init --rm -d --name ${TEST_ENV_NAME} \
       --tmpfs /tmp:exec,mode=777 \
       -v /var/lib/containerd \
       -v /var/lib/buildkit \
       -v "${REPO}:/go/src/github.com/moby/buildkit:ro" \
       -w /go/src/github.com/moby/buildkit "${TEST_ENV_IMAGE}" sleep infinity

function cleanup {
    local ORG_EXIT_CODE="${1}"
    docker kill "${TEST_ENV_NAME}" || true
    exit "${ORG_EXIT_CODE}"
}
trap 'cleanup "$?"' EXIT SIGHUP SIGINT SIGQUIT SIGTERM


docker exec ${TEST_ENV_NAME} ./hack/overlay/tools/measure.sh /result "${IMAGE}"
docker cp ${TEST_ENV_NAME}:/result "${RESULT}"

echo "result: ${RESULT}"
