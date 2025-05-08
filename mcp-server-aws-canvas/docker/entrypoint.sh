#!/bin/sh
. .venv/bin/activate
[ -z "$AWS_PROFILE" ] && echo "!!! Error mcp-server-aws-canvas requires AWS_PROFILE env var to be set." && exit 1
[ -z "$AWS_REGION" ] && echo "!!! Error mcp-server-aws-canvas requires AWS_REGION env var to be set." && exit 1

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

export MINIBRIDGE_POLICER_ENFORCE="${MINIBRIDGE_POLICER_ENFORCE:-"true"}"
export MINIBRIDGE_HEALTH_LISTEN="${MINIBRIDGE_HEALTH_LISTEN:-":8080"}"

export REGO_POLICY_RUNTIME_GUARDRAILS="$GUARDRAILS"
export REGO_POLICY_RUNTIME_BASIC_AUTH_SECRET="$BASIC_AUTH_SECRET"

if [ "$#" -gt 0 ]; then
  exec minibridge ${MINIBRIDGE_MODE} -- awslabs.nova-canvas-mcp-server "$@"
else
  exec minibridge ${MINIBRIDGE_MODE} -- awslabs.nova-canvas-mcp-server
fi

