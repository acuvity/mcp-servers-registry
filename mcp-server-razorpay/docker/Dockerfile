FROM golang:1.24-alpine3.21 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@0dcdb583396eb8d853f9822f2bf1d700cd7ae240

FROM golang:1.24-alpine3.21 as builder

ARG BUILDKIT_SBOM_SCAN_STAGE=true

WORKDIR /app
RUN apk update && apk add --no-cache git curl
RUN git clone https://github.com/razorpay/razorpay-mcp-server .
RUN git checkout v1.2.0

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o bin/razorpay-mcp-server ./cmd/razorpay-mcp-server

FROM alpine:3.21

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="remote"

LABEL org.opencontainers.image.title="mcp-server-razorpay"
LABEL org.opencontainers.image.description="Advanced payment processing with Razorpay APIs for devs and AI tools."
LABEL org.opencontainers.image.version="v1.2.0"
LABEL org.opencontainers.image.source="https://github.com/razorpay/razorpay-mcp-server"
LABEL org.opencontainers.image.licenses="MIT License"
LABEL org.opencontainers.image.author="razorpay"
LABEL org.opencontainers.image.created="2006-01-02T15:04:05Z07:00"

WORKDIR /app

ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN apk update \
    && apk add --no-cache curl

COPY --from=builder /app/bin/razorpay-mcp-server /usr/bin/razorpay-mcp-server

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
