#!/bin/bash

set -euo pipefail

CONTEXT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )/"
REPO="${CONTEXT}../../"
REGISTRY_NAME=registry2-buildkit-test

RESULT=${1}
SRC_REGISTRY=${2}
IMAGES=${@:3}

if [ "${RESULT}" == "" ] || [ "${SRC_REGISTRY}" == "" ] || [ "${IMAGES}" == "" ] ; then
    echo "specify args: <result-file> <image>"
    exit 1
fi

TEST_ENV_IMAGE="testimage-$(date '+%Y%m%d%H%M%S')"
cat <<'EOF' | docker build -t "${TEST_ENV_IMAGE}" -f - "${REPO}"
ARG CONTAINERD_VERSION=v1.6.0-rc.2
ARG RUNC_VERSION=v1.1.0
ARG CNI_PLUGINS_VERSION=v1.0.1
ARG NERDCTL_VERSION=0.16.1

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

FROM golang-base AS nerdctl-dev
ARG TARGETARCH
ARG NERDCTL_VERSION
RUN curl -sSL --output /tmp/nerdctl.tgz https://github.com/containerd/nerdctl/releases/download/v${NERDCTL_VERSION}/nerdctl-${NERDCTL_VERSION}-linux-${TARGETARCH:-amd64}.tar.gz && \
    mkdir /out/ && \
    tar zxvf /tmp/nerdctl.tgz -C /out

FROM golang-base
ARG CNI_PLUGINS_VERSION
ARG TARGETARCH
RUN apt-get update && apt-get install -y iptables curl && \
    update-alternatives --set iptables /usr/sbin/iptables-legacy && \
    mkdir -p /opt/cni/bin /etc/buildkit && \
    curl -Ls https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-${TARGETARCH:-amd64}-${CNI_PLUGINS_VERSION}.tgz | tar xzv -C /opt/cni/bin && \
    go install github.com/google/go-containerregistry/cmd/crane@v0.8.0
COPY ./hack/fixtures/cni.json /etc/buildkit/cni.json
COPY --from=containerd-dev /out/bin/containerd /out/bin/containerd-shim-runc-v2 /out/bin/ctr /usr/local/bin/
COPY --from=runc-dev /out/sbin/* /usr/local/sbin/
COPY --from=nerdctl-dev /out/nerdctl /usr/local/bin/
COPY --from=buildkit-dev /out/* /usr/local/bin/

ENTRYPOINT [ "sleep", "infinity" ]
EOF


DOCKER_COMPOSE_YAML=$(mktemp)
AUTHTMP=$(mktemp -d)
function cleanup {
    local ORG_EXIT_CODE="${1}"
    docker-compose -f "${DOCKER_COMPOSE_YAML}" down -v || true
    rm "${DOCKER_COMPOSE_YAML}" || true
    rm -rf "${AUTHTMP}" || true
    exit "${ORG_EXIT_CODE}"
}
trap 'cleanup "$?"' EXIT SIGHUP SIGINT SIGQUIT SIGTERM

mkdir ${AUTHTMP}/auth ${AUTHTMP}/certs
openssl req -subj "/C=JP/ST=Remote/L=Snapshotter/O=TestEnv/OU=Integration/CN=${REGISTRY_NAME}" \
        -addext "subjectAltName = DNS:${REGISTRY_NAME}" \
        -newkey rsa:2048 -nodes -keyout "${AUTHTMP}/certs/domain.key" \
        -x509 -days 365 -out "${AUTHTMP}/certs/domain.crt"
htpasswd -Bbn dummyuser dummypass > "${AUTHTMP}/auth/htpasswd"

TEST_ENV_NAME="testenv-$(date '+%Y%m%d%H%M%S')"
cat <<EOF > "${DOCKER_COMPOSE_YAML}"
version: "3.4"
services:
  ${TEST_ENV_NAME}:
    image: ${TEST_ENV_IMAGE}
    container_name: ${TEST_ENV_NAME}
    privileged: true
    init: true
    working_dir: /go/src/github.com/moby/buildkit
    tmpfs:
    - /tmp:exec,mode=777
    volumes:
    - "${REPO}:/go/src/github.com/moby/buildkit:ro"
    - ${AUTHTMP}:/auth
    - containerd-data:/var/lib/containerd
    - buildkit-data:/var/lib/buildkit
  ${REGISTRY_NAME}:
    image: registry:2
    container_name: ${REGISTRY_NAME}
    environment:
    - REGISTRY_AUTH=htpasswd
    - REGISTRY_AUTH_HTPASSWD_REALM="Registry Realm"
    - REGISTRY_AUTH_HTPASSWD_PATH=/auth/auth/htpasswd
    - REGISTRY_HTTP_TLS_CERTIFICATE=/auth/certs/domain.crt
    - REGISTRY_HTTP_TLS_KEY=/auth/certs/domain.key
    volumes:
    - ${AUTHTMP}:/auth
volumes:
  containerd-data:
  buildkit-data:
EOF

docker-compose -f "${DOCKER_COMPOSE_YAML}" up -d
sleep 5
docker exec ${TEST_ENV_NAME} cp /auth/certs/domain.crt /usr/local/share/ca-certificates
docker exec ${TEST_ENV_NAME} update-ca-certificates
docker exec ${TEST_ENV_NAME} nerdctl login -u dummyuser -p dummypass "${REGISTRY_NAME}:5000"
docker exec ${TEST_ENV_NAME} ./hack/blob/measure.sh /result "${REGISTRY_NAME}:5000" "${SRC_REGISTRY}" "${IMAGES}"
docker cp ${TEST_ENV_NAME}:/result "${RESULT}"

echo "result: ${RESULT}"
