FROM golang:1.24.2-alpine3.21 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@fe2187679e7835a22b9ec865d4d39a0ce6863460

FROM node:23.11.0-alpine3.21

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="remote"

LABEL org.opencontainers.image.title="mcp-server-attio"
LABEL org.opencontainers.image.description="Allows AI clients to manage records and notes in Attio CRM."
LABEL org.opencontainers.image.version="0.0.2"
LABEL org.opencontainers.image.source="https://github.com/hmk/attio-mcp-server"
LABEL org.opencontainers.image.licenses="BSD-3-Clause"
LABEL org.opencontainers.image.author="@hmk"
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

RUN npm i --omit-dev attio-mcp-server@0.0.2

EXPOSE 8000/tcp

COPY --from=minibridge /go/bin/minibridge /usr/bin
COPY ./entrypoint.sh  ./sbom.json ./policy.rego /

ENTRYPOINT ["/entrypoint.sh"]
