FROM golang:1.24.2-alpine3.21 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@8649bf59a9c0c0c63f73e4283224ea889c3a981c
FROM alpine:3.21 AS artifacts
ARG TARGETOS TARGETARCH
RUN apk update && apk add --no-cache curl file tar unzip
COPY artifacts.sh /tmp/artifacts.sh
RUN chmod a+x /tmp/artifacts.sh
RUN sh /tmp/artifacts.sh https://github.com/github/github-mcp-server/releases/download/v0.3.0/github-mcp-server_0.3.0_checksums.txt https://github.com/github/github-mcp-server/releases/download/v0.3.0/github-mcp-server_Darwin_arm64.tar.gz https://github.com/github/github-mcp-server/releases/download/v0.3.0/github-mcp-server_Darwin_x86_64.tar.gz https://github.com/github/github-mcp-server/releases/download/v0.3.0/github-mcp-server_Linux_arm64.tar.gz https://github.com/github/github-mcp-server/releases/download/v0.3.0/github-mcp-server_Linux_i386.tar.gz https://github.com/github/github-mcp-server/releases/download/v0.3.0/github-mcp-server_Linux_x86_64.tar.gz https://github.com/github/github-mcp-server/releases/download/v0.3.0/github-mcp-server_Windows_arm64.zip https://github.com/github/github-mcp-server/releases/download/v0.3.0/github-mcp-server_Windows_i386.zip https://github.com/github/github-mcp-server/releases/download/v0.3.0/github-mcp-server_Windows_x86_64.zip

FROM alpine:3.21

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="remote"

LABEL org.opencontainers.image.title="mcp-server-github"
LABEL org.opencontainers.image.description="GitHub's official MCP Server"
LABEL org.opencontainers.image.version="v0.3.0"
LABEL org.opencontainers.image.source="https://github.com/github/github-mcp-server"
LABEL org.opencontainers.image.licenses="MIT License"
LABEL org.opencontainers.image.author="github"
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
