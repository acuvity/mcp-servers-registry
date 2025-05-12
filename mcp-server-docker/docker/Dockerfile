FROM golang:1.24.2-alpine3.21 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@24197b2f066b91986db7e600c72af3bf4c1701f0

FROM ghcr.io/astral-sh/uv:python3.12-alpine

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="native"

LABEL org.opencontainers.image.title="mcp-server-docker"
LABEL org.opencontainers.image.description="Integrate with Docker to manage containers, images, volumes, and networks."
LABEL org.opencontainers.image.version="0.2.0"
LABEL org.opencontainers.image.source="https://github.com/ckreiling/mcp-server-docker"
LABEL org.opencontainers.image.licenses="GNU GENERAL PUBLIC L"
LABEL org.opencontainers.image.author="Christian Kreiling <kreiling@hey.com>"
LABEL org.opencontainers.image.created="2006-01-02T15:04:05Z07:00"

WORKDIR /app

ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN apk update \
    && apk add --no-cache curl

HEALTHCHECK CMD curl --fail http://localhost:8080 || exit 1

RUN addgroup -g 1001 -S appuser && \
    adduser -S -u 1001 -G appuser appuser && \
    addgroup appuser root && \
    mkdir -p /home/appuser/.config/minibridge && \
    chown appuser:appuser -R /app

USER appuser

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_FROZEN=true \
    UV_PROJECT_ENVIRONMENT=/app

RUN uname -sm &&  uv venv && uv pip install mcp-server-docker==0.2.0

EXPOSE 8000/tcp

VOLUME ["/var/run/docker.sock"]

COPY --from=minibridge /go/bin/minibridge /usr/bin
COPY ./entrypoint.sh  ./sbom.json ./policy.rego /

ENTRYPOINT ["/entrypoint.sh"]
