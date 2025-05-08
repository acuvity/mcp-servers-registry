FROM golang:1.24.2-alpine3.21 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@24197b2f066b91986db7e600c72af3bf4c1701f0

FROM ghcr.io/astral-sh/uv:python3.12-bookworm

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="standalone"

LABEL org.opencontainers.image.title="mcp-server-aws-terraform"
LABEL org.opencontainers.image.description="Terraform AWS best practices, infrastructure as code patterns, and security compliance with Checkov."
LABEL org.opencontainers.image.version="0.0.10"
LABEL org.opencontainers.image.source="https://github.com/awslabs/mcp/tree/main/src/terraform-mcp-server"
LABEL org.opencontainers.image.licenses="unknown"
LABEL org.opencontainers.image.author="Author"
LABEL org.opencontainers.image.created="2006-01-02T15:04:05Z07:00"

WORKDIR /app

ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN apt-get update \
    && apt-get install -y curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

HEALTHCHECK CMD curl --fail http://localhost:8080 || exit 1

RUN groupadd -r -g 1001 appuser && \
    useradd -r -u 1001 -g appuser -m appuser && \
    mkdir -p /home/appuser/.config/minibridge && \
    chown appuser:appuser -R /app

USER appuser

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_FROZEN=true \
    UV_PROJECT_ENVIRONMENT=/app

RUN uname -sm &&  uv venv && uv pip install awslabs.terraform-mcp-server==0.0.10

EXPOSE 8000/tcp

COPY --from=minibridge /go/bin/minibridge /usr/bin
COPY ./entrypoint.sh  ./sbom.json ./policy.rego /

ENTRYPOINT ["/entrypoint.sh"]
