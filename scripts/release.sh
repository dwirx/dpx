#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-dev}"
DIST_DIR="${DIST_DIR:-dist}"
PKG="./cmd/dpx"
BINARY_NAME="dpx"
DIST_PARENT="$(dirname "$DIST_DIR")"
mkdir -p "$DIST_PARENT"
DIST_DIR="$(cd "$DIST_PARENT" && pwd)/$(basename "$DIST_DIR")"
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

  ext=""
  archive_name="${BINARY_NAME}_${GOOS}_${GOARCH}.tar.gz"
  if [[ "$GOOS" == "windows" ]]; then
    ext=".exe"
    archive_name="${BINARY_NAME}_${GOOS}_${GOARCH}.zip"
  fi

  bundle_dir="$(mktemp -d "${TMPDIR:-/tmp}/dpx-release.XXXXXX")"
  trap 'rm -rf "$bundle_dir"' EXIT

  echo ">>> building $GOOS/$GOARCH"
  GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$bundle_dir/${BINARY_NAME}${ext}" "$PKG"

  cp README.md "$bundle_dir/README.md"

  if [[ "$GOOS" == "windows" ]]; then
    if command -v zip >/dev/null 2>&1; then
      (
        cd "$bundle_dir"
        zip -q "$DIST_DIR/$archive_name" "${BINARY_NAME}${ext}" README.md
      )
    elif command -v python3 >/dev/null 2>&1; then
      BUNDLE_DIR="$bundle_dir" ARCHIVE_PATH="$DIST_DIR/$archive_name" python3 <<'PY'
import os
import pathlib
import zipfile

bundle_dir = pathlib.Path(os.environ["BUNDLE_DIR"])
archive_path = pathlib.Path(os.environ["ARCHIVE_PATH"])

with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for name in ("dpx.exe", "README.md"):
        zf.write(bundle_dir / name, arcname=name)
PY
    else
      echo "zip or python3 is required to package Windows releases" >&2
      exit 1
    fi
  else
    tar -C "$bundle_dir" -czf "$DIST_DIR/$archive_name" "${BINARY_NAME}${ext}" README.md
  fi

  rm -rf "$bundle_dir"
  trap - EXIT
done

cp scripts/install.sh "$DIST_DIR/install.sh"
cp scripts/install.ps1 "$DIST_DIR/install.ps1"
chmod +x "$DIST_DIR/install.sh"

if command -v sha256sum >/dev/null 2>&1; then
  (
    cd "$DIST_DIR"
    sha256sum *.tar.gz *.zip install.sh install.ps1 > checksums.txt
  )
fi
