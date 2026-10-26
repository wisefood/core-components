#!/usr/bin/env bash
#
# Build the MinIO client that keycloak-init vendors as bin/mc.
#
# MinIO stopped serving its community downloads: dl.min.io answers 410 Gone
# for the mc binary the Dockerfile used to fetch, and the minio/mc images are
# gone too. The source is still public, so this compiles the last open-source
# release (AGPLv3, https://github.com/minio/mc) the way MinIO's own builds
# did: static, any x86-64 CPU (GOAMD64=v1), version stamped in.
#
# Run it from anywhere; it writes keycloak-init/bin/mc next to this script.
# Needs Docker. Re-run only to move to a newer release.
set -euo pipefail

MC_RELEASE="${MC_RELEASE:-RELEASE.2025-08-13T08-35-41Z}"
GO_IMAGE="${GO_IMAGE:-golang:1.24}"
HERE="$(cd "$(dirname "$0")" && pwd)"

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath \
  -e MC_RELEASE="$MC_RELEASE" \
  -v "$HERE:/out" \
  "$GO_IMAGE" sh -c '
    set -e
    git clone -q --depth 1 --branch "$MC_RELEASE" https://github.com/minio/mc /tmp/src
    cd /tmp/src
    commit=$(git rev-parse HEAD)
    stamp=$(echo "$MC_RELEASE" | sed -E "s/^RELEASE\.//; s/T([0-9]{2})-([0-9]{2})-([0-9]{2})Z/T\1:\2:\3Z/")
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -trimpath -tags kqueue \
      -ldflags "-s -w \
        -X github.com/minio/mc/cmd.Version=$stamp \
        -X github.com/minio/mc/cmd.ReleaseTag=$MC_RELEASE \
        -X github.com/minio/mc/cmd.CommitID=$commit \
        -X github.com/minio/mc/cmd.ShortCommitID=$(echo "$commit" | cut -c1-12)" \
      -o /out/mc .
  '

"$HERE/mc" --version
sha256sum "$HERE/mc" | tee "$HERE/mc.sha256"
