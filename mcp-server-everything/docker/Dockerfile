FROM golang:1.24.2-alpine3.21 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@19c423fce2d0010cee33e6b8acd3c4e88ea232c4

FROM node:23.11.0-alpine3.21

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="standalone"

LABEL org.opencontainers.image.title="mcp-server-everything"
LABEL org.opencontainers.image.description="MCP server that exercises all the features of the MCP protocol"
LABEL org.opencontainers.image.version="2025.4.8"
LABEL org.opencontainers.image.source="https://modelcontextprotocol.io"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.author="Anthropic, PBC"
LABEL org.opencontainers.image.created="2006-01-02T15:04:05Z07:00"

WORKDIR /app

ARG BUILDKIT_SBOM_SCAN_STAGE=true


RUN if command -v apt >/dev/null 2>&1; then \
  apt-get update \
  && apt-get install -y curl \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*; \
  elif command -v apk >/dev/null 2>&1; then \
  apk update \
  && apk add --no-cache curl; \
  else \
  echo "No supported package manager found." && exit 1; \
  fi



HEALTHCHECK CMD curl --fail http://localhost:8080 || exit 1

RUN if command -v groupadd >/dev/null 2>&1; then \
  groupadd -r -g 1001 appuser && \
  useradd -r -u 1001 -g appuser -m appuser; \
  else \
  addgroup -g 1001 -S appuser && \
  adduser -S -u 1001 -G appuser appuser; \
  fi && \
  mkdir -p /home/appuser/.config/minibridge && \
  chown appuser:appuser -R /app

USER appuser
RUN npm i --omit-dev @modelcontextprotocol/server-everything@2025.4.8

EXPOSE 8000/tcp

COPY ./sbom.json /
COPY --from=minibridge /go/bin/minibridge /usr/bin
COPY ./entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh"]
