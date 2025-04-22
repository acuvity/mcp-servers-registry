FROM golang:1.24.2-alpine3.21 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@cdfa8e3daef3233d2556efbf5b87b575c5216a43

FROM ghcr.io/astral-sh/uv:python3.12-alpine

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="standalone"

LABEL org.opencontainers.image.title="mcp-server-sanity-python"
LABEL org.opencontainers.image.description="A Model Context Protocol server providing tools for time queries and timezone conversions for LLMs"
LABEL org.opencontainers.image.version="0.6.2"
LABEL org.opencontainers.image.source="https://pypi.org/project/mcp-server-time/"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.author="Mariusz 'maledorak' Korzekwa <mariusz@korzekwa.dev>"
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
ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app
RUN uv venv && uv pip install mcp-server-time==0.6.2

EXPOSE 8000/tcp

COPY ./sbom.json /
COPY --from=minibridge /go/bin/minibridge /usr/bin
COPY ./entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh"]
