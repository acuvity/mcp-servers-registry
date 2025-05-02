FROM golang:1.24.2-alpine3.21 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@b764d0a9a230ebbfeeaaf91db383a57521fa7d91

FROM ghcr.io/astral-sh/uv:python3.13-alpine

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="remote"

LABEL org.opencontainers.image.title="mcp-server-codelogic"
LABEL org.opencontainers.image.description="Integrates CodeLogic's powerful codebase knowledge graphs with a Model Context Protocol (MCP) server"
LABEL org.opencontainers.image.version="1.0.2"
LABEL org.opencontainers.image.source="https://github.com/CodeLogicIncEngineering/codelogic-mcp-server"
LABEL org.opencontainers.image.licenses="<no value>"
LABEL org.opencontainers.image.author="garrmark <mgarrison@codelogic.com>"
LABEL org.opencontainers.image.created="2006-01-02T15:04:05Z07:00"

WORKDIR /app

ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN apk update \
    && apk add --no-cache curl

RUN mkdir -p /app/logs

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

RUN uname -sm &&  uv venv && uv pip install codelogic-mcp-server==1.0.2

EXPOSE 8000/tcp

COPY --from=minibridge /go/bin/minibridge /usr/bin
COPY ./entrypoint.sh  ./sbom.json ./policy.rego /

ENTRYPOINT ["/entrypoint.sh"]
