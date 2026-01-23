FROM golang:1.24-alpine3.21 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@5a873664a85bb4ba447c4edf89a48614689c1549

FROM alpine:3.21 AS artifacts

ARG TARGETOS TARGETARCH
RUN apk update && apk add --no-cache curl file tar unzip go
COPY artifacts.sh /tmp/artifacts.sh
RUN chmod a+x /tmp/artifacts.sh
RUN sh /tmp/artifacts.sh https://github.com/harness/mcp-server/releases/download/v1.0.0-beta.16/harness-mcp-server-darwin-arm64 https://github.com/harness/mcp-server/releases/download/v1.0.0-beta.16/harness-mcp-server-linux-amd64 https://github.com/harness/mcp-server/releases/download/v1.0.0-beta.16/harness-mcp-server-linux-arm64 https://github.com/harness/mcp-server/releases/download/v1.0.0-beta.16/harness-mcp-server-windows-amd64.exe https://github.com/harness/mcp-server/releases/download/v1.0.0-beta.16/harness-mcp-server-windows-arm64.exe

FROM alpine:3.21

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="remote"

LABEL org.opencontainers.image.title="mcp-server-harness"
LABEL org.opencontainers.image.description="Provides seamless integration with Harness APIs."
LABEL org.opencontainers.image.version="v1.0.0-beta.16"
LABEL org.opencontainers.image.source="https://github.com/harness/mcp-server"
LABEL org.opencontainers.image.licenses="Apache License 2.0"
LABEL org.opencontainers.image.author="harness"
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
