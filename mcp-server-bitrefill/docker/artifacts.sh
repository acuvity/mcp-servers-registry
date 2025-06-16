#!/bin/sh
set -eu

# Check environment variables
: "${TARGETARCH:?TARGETARCH environment variable is not set.}"
: "${TARGETOS:?TARGETOS environment variable is not set.}"

# Normalize arch names

case "${TARGETOS:-linux}" in
linux) norm_os=linux ;;
darwin) norm_os=darwin ;;
windows) norm_os=windows ;;
*)
  echo "Unsupported TARGETOS: $TARGETOS" >&2
  exit 1
  ;;
esac

case "${TARGETARCH:-amd64}" in
amd64 | x86_64)
  norm_arch=x86_64
  alt_arch=amd64
  ;;
arm64 | aarch64)
  norm_arch=arm64
  alt_arch=arm
  ;;
*)
  echo "Unsupported TARGETARCH: $TARGETARCH" >&2
  exit 1
  ;;
esac

MATCHED_URL=""
GOBUILD=""
for url in "$@"; do
  lc_url=$(echo "$url" | tr '[:upper:]' '[:lower:]')

  # skip checksum files
  case "$lc_url" in
  *.sha256) continue ;;
  gobuild:*)
    GOBUILD=$(echo "$lc_url" | sed 's/gobuild://g')
    ;;
  esac

  # common pattern for names, in order with a fallback on OS only for amd64
  patterns="${norm_os}_${norm_arch} ${norm_os}_${alt_arch} ${norm_os}-${norm_arch} ${norm_os}-${alt_arch} ${norm_arch} ${alt_arch} ${norm_os}"

  set -f
  for pat in $patterns; do
    case "$lc_url" in
    *"$pat"*)
      MATCHED_URL=$url
      set +f
      break 2
      ;;
    esac
  done
done

# Verify we found a match
if [ -z "$MATCHED_URL" ] && [ -z "$GOBUILD" ]; then
  echo "No matching URL/build found for TARGETOS=$TARGETOS TARGETARCH=$TARGETARCH"
  exit 1
fi

mkdir -p /tmp/binaries

if [ -n "$MATCHED_URL" ]; then

  echo "Downloading: $MATCHED_URL"
  TMPFILE=$(mktemp)
  curl -fSL "$MATCHED_URL" -o "$TMPFILE"

  # Extract based on archive type
  case "$MATCHED_URL" in
  *.tar.gz | *.tgz)
    tar -xzf "$TMPFILE" -C /tmp/binaries
    ;;
  *.zip)
    unzip -qq "$TMPFILE" -d /tmp/binaries
    ;;
  *)
    FILENAME=$(basename "$MATCHED_URL")
    BINNAME=$(echo "$FILENAME" | sed -E 's/-linux-(arm64|amd64|x86_64|i386|ppc64le|s390x)$//')
    mv "$TMPFILE" "/tmp/binaries/$BINNAME"
    ;;
  esac

fi

if [ -n "$GOBUILD" ]; then

  echo "Building go artifacts"
  export GOBIN=/tmp/binaries
  oldIFS=$IFS
  IFS=','
  for bin in $GOBUILD; do
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install "$bin"
  done
  IFS=$oldIFS
fi

cd /tmp/binaries

BINARIES=$(find . -type f -exec file {} \; | awk -F: '/executable/ {print $1}')

if [ -z "$BINARIES" ]; then
  echo "No executables found in /tmp/binaries" >&2
  exit 1
fi

for BIN_PATH in $BINARIES; do
  BIN_NAME=$(basename "$BIN_PATH")
  mv "$BIN_PATH" "./$BIN_NAME"
  chmod +x "./$BIN_NAME"
  echo "Kept binary: $BIN_NAME"
done

for FILE in ./*; do
  keep=0
  for BIN_PATH in $BINARIES; do
    if [ "./$(basename "$BIN_PATH")" = "$FILE" ]; then
      keep=1
      break
    fi
  done
  if [ $keep -eq 0 ] && [ "$FILE" != "./$(basename "$0")" ]; then
    rm -rf "$FILE"
  fi
done
