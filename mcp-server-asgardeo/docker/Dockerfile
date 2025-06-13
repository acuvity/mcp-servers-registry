FROM golang:1.24-alpine3.21 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@0dcdb583396eb8d853f9822f2bf1d700cd7ae240

FROM alpine:3.21 AS artifacts

ARG TARGETOS TARGETARCH
RUN apk update && apk add --no-cache curl file tar unzip go
COPY artifacts.sh /tmp/artifacts.sh
RUN chmod a+x /tmp/artifacts.sh
RUN sh /tmp/artifacts.sh https://github.com/asgardeo/asgardeo-mcp-server/releases/download/v0.1.0/asgardeo_mcp_server_darwin-v0.1.0.zip https://github.com/asgardeo/asgardeo-mcp-server/releases/download/v0.1.0/asgardeo_mcp_server_darwin-v0.1.0.zip.sha256 https://github.com/asgardeo/asgardeo-mcp-server/releases/download/v0.1.0/asgardeo_mcp_server_linux-arm-v0.1.0.zip https://github.com/asgardeo/asgardeo-mcp-server/releases/download/v0.1.0/asgardeo_mcp_server_linux-arm-v0.1.0.zip.sha256 https://github.com/asgardeo/asgardeo-mcp-server/releases/download/v0.1.0/asgardeo_mcp_server_linux-v0.1.0.zip https://github.com/asgardeo/asgardeo-mcp-server/releases/download/v0.1.0/asgardeo_mcp_server_linux-v0.1.0.zip.sha256

FROM alpine:3.21

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="remote"

LABEL org.opencontainers.image.title="mcp-server-asgardeo"
LABEL org.opencontainers.image.description="MCP server to interact with your Asgardeo organization through LLM tools."
LABEL org.opencontainers.image.version="v0.1.0"
LABEL org.opencontainers.image.source="https://github.com/asgardeo/asgardeo-mcp-server"
LABEL org.opencontainers.image.licenses="Apache License 2.0"
LABEL org.opencontainers.image.author="asgardeo"
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
