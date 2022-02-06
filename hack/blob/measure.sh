#!/bin/bash

set -euo pipefail

CONTEXT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )/"

RESULT=${1}
REGISTRY=${2}
SRC_REGISTRY=${3}
IMAGES=${@:4}

if [ "${RESULT}" == "" ] || [ "${REGISTRY}" == "" ] || [ "${SRC_REGISTRY}" == "" ] || [ "${IMAGES}" == "" ] ; then
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

echo "worker,image,time" > "${RESULT}"

function build {
    IMG="${1}"
    RES_FILE="${2}"
    OPTS="${@:3}"

    "${CONTEXT}"/run-buildkit.sh ${OPTS}

    echo "===== Creating image B ====="
    cat <<EOF > "${TMP_CONTEXT}/Dockerfile"
FROM ${REGISTRY}/${IMG}
RUN echo hello > /hello
EOF
    cat "${TMP_CONTEXT}/Dockerfile"
    buildctl build --progress=plain --frontend=dockerfile.v0 \
             --local context=${TMP_CONTEXT} --local dockerfile=${TMP_CONTEXT} \
             --output type=image,oci-mediatypes=true,name="${REGISTRY}/${IMG}-b-zstd",compression=zstd,force-compression=true,push=true

    "${CONTEXT}"/run-buildkit.sh ${OPTS}
    
    echo "===== Creating image A with converting gzip => zstd ====="
    cat <<EOF > "${TMP_CONTEXT}/Dockerfile"
FROM ${REGISTRY}/${IMG}
RUN echo hi > /hi
EOF
    cat "${TMP_CONTEXT}/Dockerfile"
    buildctl build --progress=plain --frontend=dockerfile.v0 \
             --local context=${TMP_CONTEXT} --local dockerfile=${TMP_CONTEXT} \
             --output type=image,oci-mediatypes=true,name="${REGISTRY}/${IMG}-a-gzip",compression=gzip,force-compression=true,push=true
    buildctl build --progress=plain --frontend=dockerfile.v0 \
             --local context=${TMP_CONTEXT} --local dockerfile=${TMP_CONTEXT} \
             --output type=image,oci-mediatypes=true,name="${REGISTRY}/${IMG}-a-zstd",compression=zstd,force-compression=true,push=true

    echo "===== Pulling image B with converting zstd => gzip ====="
    cat <<EOF > "${TMP_CONTEXT}/Dockerfile"
FROM ${REGISTRY}/${IMG}-b-zstd
EOF
    echo "" > "${TMP_LOG}"
    buildctl build --progress=plain --frontend=dockerfile.v0 \
             --local context=${TMP_CONTEXT} --local dockerfile=${TMP_CONTEXT} \
             --output type=oci,dest=${TMP_WORKSPACE}/img.tar,oci-mediatypes=true,compression=gzip,force-compression=true > "${TMP_LOG}" 2>&1
    cat "${TMP_LOG}"
    if cat "${TMP_LOG}" | grep -E 'exporting layers [0-9\.]+s done' ; then
        cat "${TMP_LOG}" | grep -E 'exporting layers [0-9\.]+s done' | sed -E 's/.*exporting layers ([0-9\.]+)s done.*/\1/g' > "${RES_FILE}"
    elif cat "${TMP_LOG}" | grep -E 'exporting layers done' ; then
        echo "0" > "${RES_FILE}"
    else
        echo "no matching result log"
        exit 1
    fi
}

function measure {
    WORKER_NAME="${1}"
    OPTS="${@:2}"
    for IMG in $IMAGES ; do
        RES_FILE="${TMP_WORKSPACE}-${WORKER_NAME}-${IMG}"
        echo "========================================================="
        echo "result: ${RES_FILE}"
        echo "========================================================="
        WORKER="${WORKER_NAME}" build "${IMG}" "${RES_FILE}" ${OPTS}
        echo -n "${WORKER_NAME},${IMG}," >> "${RESULT}"
        cat "${RES_FILE}" >> "${RESULT}"
    done
}

# Prepare images
for IMG in $IMAGES ; do
    crane copy "${SRC_REGISTRY}/${IMG}" "${REGISTRY}/${IMG}" 
done

# OCI worker
measure "oci"

# containerd worker
measure "containerd" --oci-worker=false --containerd-worker=true
