FROM golang:1.24-alpine3.21 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@0dcdb583396eb8d853f9822f2bf1d700cd7ae240

FROM ghcr.io/astral-sh/uv:python3.13-alpine as builder

ARG BUILDKIT_SBOM_SCAN_STAGE=true

WORKDIR /app
RUN apk update && apk add --no-cache git curl
RUN git clone https://github.com/Aiven-Open/mcp-aiven .
RUN git checkout 297e5bd

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
RUN rm -f .python-version \
    && ([ ! -f uv.lock ] && uv lock || true) \
    && uv sync --frozen --no-dev --no-editable \
    && uv pip install .

FROM ghcr.io/astral-sh/uv:python3.13-alpine

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="remote"

LABEL org.opencontainers.image.title="mcp-server-aiven"
LABEL org.opencontainers.image.description="Navigate your Aiven projects and interact with PostgreSQL, Kafka, ClickHouse and OpenSearch services"
LABEL org.opencontainers.image.version="297e5bd"
LABEL org.opencontainers.image.source="https://github.com/Aiven-Open/mcp-aiven"
LABEL org.opencontainers.image.licenses="Apache License 2.0"
LABEL org.opencontainers.image.author="Aiven-Open"
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

COPY --from=builder /app/.venv /app/.venv

EXPOSE 8000/tcp

COPY --from=minibridge /go/bin/minibridge /usr/bin
COPY ./entrypoint.sh  ./sbom.json ./policy.rego /

ENTRYPOINT ["/entrypoint.sh"]
