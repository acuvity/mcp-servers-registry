FROM golang:1.24-alpine3.21 AS minibridge

ENV GO111MODULE=on
ARG TARGETOS TARGETARCH
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install go.acuvity.ai/minibridge@0dcdb583396eb8d853f9822f2bf1d700cd7ae240

FROM alpine:3.21 AS artifacts

ARG TARGETOS TARGETARCH
RUN apk update && apk add --no-cache curl file tar unzip go
COPY artifacts.sh /tmp/artifacts.sh
RUN chmod a+x /tmp/artifacts.sh
RUN sh /tmp/artifacts.sh https://github.com/projectdiscovery/alterx/releases/download/v0.0.6/alterx_0.0.6_linux_arm64.zip https://github.com/projectdiscovery/alterx/releases/download/v0.0.6/alterx_0.0.6_linux_amd64.zip

FROM node:23.11.0-alpine3.21 as builder

ARG BUILDKIT_SBOM_SCAN_STAGE=true

WORKDIR /app
RUN apk update && apk add --no-cache git curl
RUN git clone https://github.com/cyproxio/mcp-for-security .
RUN git checkout 6190e55
RUN mv alterx-mcp /tmp && rm -rf * && mv /tmp/alterx-mcp/* .
RUN npm ci --omit-dev && npm run build
RUN mkdir -p build \
 && for d in src dist; do \
      if [ -d "$d" ]; then \
        mv "$d"/* build/; \
      fi; \
    done

FROM node:23.11.0-alpine3.21

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="native"

LABEL org.opencontainers.image.title="mcp-server-alterx"
LABEL org.opencontainers.image.description="Pattern-based wordlist generator for subdomain discovery using Alterx permutation tool"
LABEL org.opencontainers.image.version="6190e55"
LABEL org.opencontainers.image.source="https://github.com/cyproxio/mcp-for-security/tree/HEAD/alterx-mcp"
LABEL org.opencontainers.image.licenses="MIT License"
LABEL org.opencontainers.image.author="cyproxio"
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

ENV NODE_ENV=production

USER appuser

COPY --from=builder /app/package.json ./
COPY --from=builder /app/package-lock.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/build ./build

EXPOSE 8000/tcp

COPY --from=minibridge /go/bin/minibridge /usr/bin
COPY ./entrypoint.sh  ./sbom.json ./policy.rego /

ENTRYPOINT ["/entrypoint.sh"]
