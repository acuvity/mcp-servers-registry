#!/bin/sh
set -eu

# Check environment variables
if [ -z "${TARGETARCH:-}" ]; then
  echo "TARGETARCH environment variable is not set."
  exit 1
fi

if [ -z "${TARGETOS:-}" ]; then
  echo "TARGETOS environment variable is not set."
  exit 1
fi

case "$TARGETARCH" in
amd64) norm_arch="x86_64" ;;
386) norm_arch="i386" ;;
arm64) norm_arch="arm64" ;;
*) norm_arch="$TARGETARCH" ;;
esac

case "$TARGETOS" in
linux) norm_os="linux" ;;
darwin) norm_os="darwin" ;;
windows) norm_os="windows" ;;
*) norm_os="$TARGETOS" ;;
esac

MATCHED_URL=""
for url in "$@"; do
  lc_url=$(echo "$url" | tr '[:upper:]' '[:lower:]')
  if echo "$lc_url" | grep -q "$norm_os" && echo "$lc_url" | grep -q "$norm_arch"; then
    MATCHED_URL="$url"
    break
  fi
done

# Verify we found a match
if [ -z "$MATCHED_URL" ]; then
  echo "No matching URL found for TARGETOS=$TARGETOS TARGETARCH=$TARGETARCH"
  exit 1
fi

echo "Downloading: $MATCHED_URL"
curl -fsSL "$MATCHED_URL" -o /tmp/archive.tar.gz

mkdir -p /tmp/binaries
tar -xzf /tmp/archive.tar.gz -C /tmp/binaries

# Filter and clean binaries
for file in /tmp/binaries/*; do
  [ -f "$file" ] || continue
  if file "$file" | grep -qi "executable"; then
    chmod +x "$file"
  else
    echo "Removing non-binary: $file"
    rm -f "$file"
  fi
done

rm -f /tmp/archive.tar.gz
