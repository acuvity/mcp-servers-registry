FROM golang:1.24.2-alpine3.21 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@8649bf59a9c0c0c63f73e4283224ea889c3a981c

FROM ghcr.io/astral-sh/uv:python3.10-bookworm

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="remote"

LABEL org.opencontainers.image.title="mcp-server-chroma"
LABEL org.opencontainers.image.description="Embedding database for LLM applications with advanced search capabilities."
LABEL org.opencontainers.image.version="0.2.2"
LABEL org.opencontainers.image.source="https://github.com/chroma-core/chroma-mcp"
LABEL org.opencontainers.image.licenses="nil"
LABEL org.opencontainers.image.author="Author"
LABEL org.opencontainers.image.created="2006-01-02T15:04:05Z07:00"

WORKDIR /app

ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN apt-get update \
    && apt-get install -y curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


HEALTHCHECK CMD curl --fail http://localhost:8080 || exit 1

RUN groupadd -r -g 1001 appuser && \
    useradd -r -u 1001 -g appuser -m appuser && \
    mkdir -p /home/appuser/.config/minibridge && \
    chown appuser:appuser -R /app

USER appuser

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_FROZEN=true \
    UV_PROJECT_ENVIRONMENT=/app

RUN uv venv && uv pip install chroma-mcp==0.2.2

EXPOSE 8000/tcp

COPY --from=minibridge /go/bin/minibridge /usr/bin
COPY ./entrypoint.sh  ./sbom.json ./policy.rego /

ENTRYPOINT ["/entrypoint.sh"]
