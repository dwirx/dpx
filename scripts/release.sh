#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-dev}"
DIST_DIR="${DIST_DIR:-dist}"
PKG="./cmd/dpx"
PLATFORMS=(
  linux/amd64
  linux/arm64
  darwin/amd64
  darwin/arm64
  windows/amd64
  windows/arm64
)

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

for target in "${PLATFORMS[@]}"; do
  IFS=/ read -r GOOS GOARCH <<<"$target"
  name="dpx_${VERSION}_${GOOS}_${GOARCH}"
  ext=""
  if [[ "$GOOS" == "windows" ]]; then
    ext=".exe"
  fi

  bundle_dir="$DIST_DIR/$name"
  mkdir -p "$bundle_dir"

  echo ">>> building $GOOS/$GOARCH"
  GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$bundle_dir/dpx$ext" "$PKG"

  cp README.md "$bundle_dir/README.md"

  if [[ "$GOOS" == "windows" ]] && command -v zip >/dev/null 2>&1; then
    (cd "$DIST_DIR" && zip -qr "${name}.zip" "$name")
  else
    tar -C "$DIST_DIR" -czf "$DIST_DIR/${name}.tar.gz" "$name"
  fi

done

if command -v sha256sum >/dev/null 2>&1; then
  (
    cd "$DIST_DIR"
    sha256sum *.tar.gz *.zip 2>/dev/null > checksums.txt || sha256sum *.tar.gz > checksums.txt
  )
fi
