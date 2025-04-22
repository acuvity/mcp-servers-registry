#!/bin/sh
export PATH="/app/node_modules/.bin:${PATH}"
export MEMORY_FILE_PATH=${MEMORY_FILE_PATH:-"/data/default.json"}

if [ -z "$MINIBRIDGE_MODE" ]; then
  # check if stdin in open
  if [ -p /dev/stdin ]; then
    MINIBRIDGE_MODE=aio
  else
    export MINIBRIDGE_LISTEN=":8000"
    MINIBRIDGE_MODE=${MINIBRIDGE_MODE:-aio}
  fi
fi

if [ -s /sbom.json ]; then
  export MINIBRIDGE_SBOM=/sbom.json
fi

exec minibridge ${MINIBRIDGE_MODE} --health-enable -- mcp-server-memory "$@"

