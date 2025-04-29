FROM golang:1.24.2-alpine3.21 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@834d659bbe022305f35e00a0aaf62b2a13ad84db

FROM node:23.11.0-alpine3.21

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="remote"

LABEL org.opencontainers.image.title="mcp-server-brave-search"
LABEL org.opencontainers.image.description="MCP server for Brave Search API integration"
LABEL org.opencontainers.image.version="0.6.2"
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
RUN npm i --omit-dev @modelcontextprotocol/server-brave-search@0.6.2

EXPOSE 8000/tcp

COPY --from=minibridge /go/bin/minibridge /usr/bin
COPY ./entrypoint.sh  ./sbom.json ./policy.rego /

ENTRYPOINT ["/entrypoint.sh"]
