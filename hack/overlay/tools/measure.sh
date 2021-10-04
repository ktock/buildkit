#!/bin/bash

set -euo pipefail

CONTEXT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )/"

RESULT=${1}
IMAGES=${@:2}

if [ "${RESULT}" == "" ] || [ "${IMAGES}" == "" ] ; then
    echo "specify args: <result-file> <image>..."
    exit 1
fi

TMP_WORKSPACE=$(mktemp -d)
function cleanup {
    local ORG_EXIT_CODE="${1}"
    rm -rf "${TMP_WORKSPACE}" || true
    exit "${ORG_EXIT_CODE}"
}
trap 'cleanup "$?"' EXIT SIGHUP SIGINT SIGQUIT SIGTERM

TMP_LOG=${TMP_WORKSPACE}/tmp-log
echo "TMP_LOG = ${TMP_LOG}"
TMP_CONTEXT=${TMP_WORKSPACE}/context
mkdir -p ${TMP_CONTEXT}

echo "worker,image,is-overlay,compression,size,time" > "${RESULT}"

function export_file {
    IMG="${1}"
    SIZE="${2}"
    COMPRESSION="${3}"
    OPTS="${@:4}"
    cat <<EOF > "${TMP_CONTEXT}/Dockerfile"
FROM $IMG
RUN head -c ${SIZE} </dev/urandom > /sample
EOF
    cat "${TMP_CONTEXT}/Dockerfile"
    IMGNAME=$(echo ${IMG} | sed 's|[/:]|-|g')
    "${CONTEXT}"/run-buildkit.sh ${OPTS}
    buildctl build --progress=plain --frontend=dockerfile.v0 \
             --local context=${TMP_CONTEXT} --local dockerfile=${TMP_CONTEXT} \
             --output type=oci,dest=${TMP_WORKSPACE}/${IMGNAME}.tar,compression=${COMPRESSION} 2>&1
}

function measure {
    WORKER_NAME="${1}"
    OPTS="${@:2}"
    for IMG in $IMAGES ; do
        for OVERLAY in "true" "false" ; do
            for COMPRESSION in "gzip" ; do
                for SIZE in "1G" "500M" "100M" "50M" ; do
                    WORKER="${WORKER_NAME}" BUILDKIT_DEBUG_FORCE_OVERLAY_DIFF=${OVERLAY} export_file "${IMG}" "${SIZE}" "${COMPRESSION}" ${OPTS} > "${TMP_LOG}"
                    echo -n "${WORKER_NAME},${IMG},${OVERLAY},${COMPRESSION},${SIZE}," >> "${RESULT}"
                    cat "${TMP_LOG}" | grep "exporting layers " | sed -E 's/.*exporting layers ([0-9\.]+)s done.*/\1/g' >> "${RESULT}"
                    cat "${TMP_LOG}"
                done
            done
        done
    done
}

# OCI worker
measure "oci"

# containerd worker
measure "containerd" --oci-worker=false --containerd-worker=true
