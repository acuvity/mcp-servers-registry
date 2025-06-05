FROM golang:1.24 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@0dcdb583396eb8d853f9822f2bf1d700cd7ae240

FROM node:23-slim

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="remote"

LABEL org.opencontainers.image.title="mcp-server-azure"
LABEL org.opencontainers.image.description="Integrates AI agents with Azure services for enhanced functionality."
LABEL org.opencontainers.image.version="0.1.2"
LABEL org.opencontainers.image.source="https://github.com/Azure/azure-mcp"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.author="Microsoft Corporation"
LABEL org.opencontainers.image.created="2006-01-02T15:04:05Z07:00"

WORKDIR /app

ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN apt-get update \
    && apt-get install -y curl libicu-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

HEALTHCHECK CMD curl --fail http://localhost:8080 || exit 1

RUN groupadd -r -g 1001 appuser && \
    useradd -r -u 1001 -g appuser -m appuser && \
    mkdir -p /home/appuser/.config/minibridge && \
    chown appuser:appuser -R /app

ENV NODE_ENV=production

USER appuser

RUN npm i --omit-dev @azure/mcp@0.1.2

EXPOSE 8000/tcp

COPY --from=minibridge /go/bin/minibridge /usr/bin
COPY ./entrypoint.sh  ./sbom.json ./policy.rego /

ENTRYPOINT ["/entrypoint.sh"]
