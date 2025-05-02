#!/bin/sh
. .venv/bin/activate
[ -z "$AWS_PROFILE" ] && echo "!!! Error mcp-server-aws-lambda requires AWS_PROFILE env var to be set." && exit 1
[ -z "$AWS_REGION" ] && echo "!!! Error mcp-server-aws-lambda requires AWS_REGION env var to be set." && exit 1
[ -z "$FUNCTION_LIST" ] && echo "!!! Error mcp-server-aws-lambda requires FUNCTION_LIST env var to be set." && exit 1
[ -z "$FUNCTION_PREFIX" ] && echo "!!! Error mcp-server-aws-lambda requires FUNCTION_PREFIX env var to be set." && exit 1
[ -z "$FUNCTION_TAG_KEY" ] && echo "!!! Error mcp-server-aws-lambda requires FUNCTION_TAG_KEY env var to be set." && exit 1
[ -z "$FUNCTION_TAG_VALUE" ] && echo "!!! Error mcp-server-aws-lambda requires FUNCTION_TAG_VALUE env var to be set." && exit 1

if [ -z "$MINIBRIDGE_MODE" ]; then
  # check if stdin in open
  if [ -p /dev/stdin ]; then
    MINIBRIDGE_MODE=aio
  else
    export MINIBRIDGE_LISTEN=":8000"
    MINIBRIDGE_MODE=${MINIBRIDGE_MODE:-aio}
  fi
fi

MINIBRIDGE_SBOM=${MINIBRIDGE_SBOM:-"/sbom.json"}
if [ -n "$MINIBRIDGE_SBOM" ] && [ -s "$MINIBRIDGE_SBOM" ]; then
  export MINIBRIDGE_SBOM
else
  unset MINIBRIDGE_SBOM
fi

MINIBRIDGE_POLICER_REGO_POLICY=${MINIBRIDGE_POLICER_REGO_POLICY:-"/policy.rego"}
if [ -n "$MINIBRIDGE_POLICER_REGO_POLICY" ] && [ -s "$MINIBRIDGE_POLICER_REGO_POLICY" ]; then
  export MINIBRIDGE_POLICER_TYPE="${MINIBRIDGE_POLICER_TYPE:-rego}"
  export MINIBRIDGE_POLICER_REGO_POLICY
else
  unset MINIBRIDGE_POLICER_REGO_POLICY
  if [ "$MINIBRIDGE_POLICER_TYPE" = "rego" ]; then
    unset MINIBRIDGE_POLICER_TYPE
  fi
fi

export MINIBRIDGE_POLICER_ENFORCE="${MINIBRIDGE_POLICER_ENFORCE:-"false"}"
export MINIBRIDGE_HEALTH_LISTEN="${MINIBRIDGE_HEALTH_LISTEN:-":8080"}"

exec minibridge ${MINIBRIDGE_MODE} -- awslabs.lambda-mcp-server "$@"

