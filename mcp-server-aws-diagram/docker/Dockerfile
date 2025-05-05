FROM golang:1.24.2-alpine3.21 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@fe2187679e7835a22b9ec865d4d39a0ce6863460

FROM ghcr.io/astral-sh/uv:python3.12-alpine

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="standalone"

LABEL org.opencontainers.image.title="mcp-server-aws-diagram"
LABEL org.opencontainers.image.description="Create diagrams using the Python diagrams package: sequence, flow, and class diagrams."
LABEL org.opencontainers.image.version="0.9.3"
LABEL org.opencontainers.image.source="https://github.com/awslabs/mcp/tree/main/src/aws-diagram-mcp-server"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.author="AWSLabs MCP <203918161+awslabs-mcp@users.noreply.github.com>"
LABEL org.opencontainers.image.created="2006-01-02T15:04:05Z07:00"

WORKDIR /app

ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN apk update \
    && apk add --no-cache curl

HEALTHCHECK CMD curl --fail http://localhost:8080 || exit 1

RUN addgroup -g 1001 -S appuser && \
    adduser -S -u 1001 -G appuser appuser && \
    mkdir -p /home/appuser/.config/minibridge && \
    chown appuser:appuser -R /app

USER appuser

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_FROZEN=true \
    UV_PROJECT_ENVIRONMENT=/app

RUN uname -sm &&  uv venv && uv pip install awslabs.aws-diagram-mcp-server==0.9.3

EXPOSE 8000/tcp

COPY --from=minibridge /go/bin/minibridge /usr/bin
COPY ./entrypoint.sh  ./sbom.json ./policy.rego /

ENTRYPOINT ["/entrypoint.sh"]
