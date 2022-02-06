#!/bin/bash

set -euo pipefail

CONTAINERD_ROOT=/var/lib/containerd/
BUILDKITD_ROOT=/var/lib/buildkit/
BUILDKITD_SOCKET=/run/buildkit/buildkitd.sock

RETRYNUM=30
RETRYINTERVAL=1
TIMEOUTSEC=180
function retry {
    local SUCCESS=false
    for i in $(seq ${RETRYNUM}) ; do
        if eval "timeout ${TIMEOUTSEC} ${@}" ; then
            SUCCESS=true
            break
        fi
        echo "Fail(${i}). Retrying..."
        sleep ${RETRYINTERVAL}
    done
    if [ "${SUCCESS}" == "true" ] ; then
        return 0
    else
        return 1
    fi
}

function kill_all {
    if [ "${1}" != "" ] ; then
        ps aux | grep "${1}" | grep -v "run-buildkit.sh" | grep -v grep | sed -E 's/ +/ /g' | cut -f 2 -d ' ' | xargs -I{} kill -9 {} || true
    fi
}

function cleanup {
    rm -rf "${CONTAINERD_ROOT}"*
    rm -rf "${BUILDKITD_ROOT}"*
    rm "${BUILDKITD_SOCKET}" || true
    rm /run/containerd/containerd.sock || true
}

echo "cleaning up the environment..."
ps auxww
kill_all " containerd"
kill_all " buildkitd"
cleanup

if [ "${WORKER}" == "containerd" ] ; then
    echo "running containerd..."
    containerd &
    retry ctr version
fi

echo "running buildkitd..."
buildkitd $@ &
retry ls "${BUILDKITD_SOCKET}"
