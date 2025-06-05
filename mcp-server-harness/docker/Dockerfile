FROM golang:1.24 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@0dcdb583396eb8d853f9822f2bf1d700cd7ae240

FROM golang:1.24 AS builder
ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN git clone https://github.com/harness/mcp-server sources
RUN cd sources && git checkout v1.0.0-beta

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    cd sources && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o bin/harness-mcp-server ./cmd/harness-mcp-server

FROM alpine:3.21

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="remote"

LABEL org.opencontainers.image.title="mcp-server-harness"
LABEL org.opencontainers.image.description="Provides seamless integration with Harness APIs."
LABEL org.opencontainers.image.version="v1.0.0-beta"
LABEL org.opencontainers.image.source="https://github.com/harness/mcp-server"
LABEL org.opencontainers.image.licenses="Apache License 2.0"
LABEL org.opencontainers.image.author="harness"
LABEL org.opencontainers.image.created="2006-01-02T15:04:05Z07:00"

WORKDIR /app

ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN apk update \
    && apk add --no-cache curl

COPY --from=builder /go/sources/bin/harness-mcp-server /usr/bin/harness-mcp-server

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
