#!/usr/bin/env bash
set -e

GO=${GO:-$(command -v go 2>/dev/null || echo "/home/kali/go/bin/go")}

BINARY="sqlz"
CMD="./cmd/sqlz"
OUT="dist"

mkdir -p "$OUT"

build() {
    local os=$1 arch=$2
    local name="${BINARY}_${os}_${arch}"
    [[ "$os" == "windows" ]] && name="${name}.exe"

    echo "Building $name..."
    GOOS=$os GOARCH=$arch "$GO" build -trimpath -ldflags="-s -w" -o "${OUT}/${name}" "$CMD"
}

build linux   amd64
build linux   arm64
build linux   386
build windows amd64
build windows arm64
build windows 386
build darwin  amd64
build darwin  arm64

echo ""
echo "Done. Binaries in ./${OUT}/:"
ls -lh "${OUT}/"
