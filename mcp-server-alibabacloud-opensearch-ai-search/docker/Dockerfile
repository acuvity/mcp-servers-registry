FROM golang:1.24-alpine3.21 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@0dcdb583396eb8d853f9822f2bf1d700cd7ae240

FROM ghcr.io/astral-sh/uv:python3.12-alpine as builder

ARG BUILDKIT_SBOM_SCAN_STAGE=true

WORKDIR /app
RUN apk update && apk add --no-cache git curl
RUN git clone https://github.com/aliyun/alibabacloud-opensearch-mcp-server .
RUN git checkout 545d264
RUN mv aisearch-mcp-server /tmp && rm -rf * && mv /tmp/aisearch-mcp-server/* .

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
RUN rm -f .python-version \
    && ([ ! -f uv.lock ] && uv lock || true) \
    && uv sync --frozen --no-dev --no-editable \
    && uv pip install .

FROM ghcr.io/astral-sh/uv:python3.12-alpine

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="remote"

LABEL org.opencontainers.image.title="mcp-server-alibabacloud-opensearch-ai-search"
LABEL org.opencontainers.image.description="Universal interface between AI Agents and OpenSearch AI Search Platform."
LABEL org.opencontainers.image.version="545d264"
LABEL org.opencontainers.image.source="https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/aisearch-mcp-server"
LABEL org.opencontainers.image.licenses="Apache License 2.0"
LABEL org.opencontainers.image.author="aliyun"
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
