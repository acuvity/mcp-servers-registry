FROM golang:1.24.2-alpine3.21 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@24197b2f066b91986db7e600c72af3bf4c1701f0
FROM alpine:3.21 AS artifacts
ARG TARGETOS TARGETARCH
RUN apk update && apk add --no-cache curl file tar unzip
COPY artifacts.sh /tmp/artifacts.sh
RUN chmod a+x /tmp/artifacts.sh
RUN sh /tmp/artifacts.sh https://github.com/acuvity/mcp-server-microsoft-graph/releases/download/1.0.1/mcp-server-microsoft-graph_1.0.1_checksums.txt https://github.com/acuvity/mcp-server-microsoft-graph/releases/download/1.0.1/mcp-server-microsoft-graph_Darwin_arm64.tar.gz https://github.com/acuvity/mcp-server-microsoft-graph/releases/download/1.0.1/mcp-server-microsoft-graph_Darwin_x86_64.tar.gz https://github.com/acuvity/mcp-server-microsoft-graph/releases/download/1.0.1/mcp-server-microsoft-graph_Linux_arm64.tar.gz https://github.com/acuvity/mcp-server-microsoft-graph/releases/download/1.0.1/mcp-server-microsoft-graph_Linux_x86_64.tar.gz

FROM alpine:3.21

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="remote"

LABEL org.opencontainers.image.title="mcp-server-microsoft-graph"
LABEL org.opencontainers.image.description="Connect to microsoft API to get applications, sites users and more."
LABEL org.opencontainers.image.version="1.0.1"
LABEL org.opencontainers.image.source="https://github.com/acuvity/mcp-server-microsoft-graph"
LABEL org.opencontainers.image.licenses="unknown"
LABEL org.opencontainers.image.author="acuvity"
LABEL org.opencontainers.image.created="2006-01-02T15:04:05Z07:00"

WORKDIR /app

ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN apk update \
    && apk add --no-cache curl

COPY --from=artifacts /tmp/binaries /usr/local/bin

HEALTHCHECK CMD curl --fail http://localhost:8080 || exit 1

RUN addgroup -g 1001 -S appuser && \
    adduser -S -u 1001 -G appuser appuser && \
    mkdir -p /home/appuser/.config/minibridge && \
    chown appuser:appuser -R /app

USER appuser

EXPOSE 8000/tcp

COPY --from=minibridge /go/bin/minibridge /usr/bin
COPY ./entrypoint.sh  ./sbom.json ./policy.rego /

ENTRYPOINT ["/entrypoint.sh"]
