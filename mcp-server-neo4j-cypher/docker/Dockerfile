FROM golang:1.24.2-alpine3.21 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@8649bf59a9c0c0c63f73e4283224ea889c3a981c

FROM ghcr.io/astral-sh/uv:python3.12-alpine

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="remote"

LABEL org.opencontainers.image.title="mcp-server-neo4j-cypher"
LABEL org.opencontainers.image.description="Manage Cypher graph queries between LLMs and Neo4j with natural language queries."
LABEL org.opencontainers.image.version="0.2.1"
LABEL org.opencontainers.image.source="https://github.com/neo4j-contrib/mcp-neo4j"
LABEL org.opencontainers.image.licenses="nil"
LABEL org.opencontainers.image.author="Author"
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

RUN uv venv && uv pip install mcp-neo4j-cypher==0.2.1

EXPOSE 8000/tcp

COPY --from=minibridge /go/bin/minibridge /usr/bin
COPY ./entrypoint.sh  ./sbom.json ./policy.rego /

ENTRYPOINT ["/entrypoint.sh"]
