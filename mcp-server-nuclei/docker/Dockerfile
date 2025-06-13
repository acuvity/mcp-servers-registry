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
RUN sh /tmp/artifacts.sh gobuild:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

FROM node:23.11.0-slim as builder

ARG BUILDKIT_SBOM_SCAN_STAGE=true

WORKDIR /app
RUN apt-get update && apt-get -y install git curl python3 make g++
RUN git clone https://github.com/cyproxio/mcp-for-security .
RUN git checkout 6190e55
RUN mv nuclei-mcp /tmp && rm -rf * && mv /tmp/nuclei-mcp/* .
RUN npm ci --omit-dev && npm run build
RUN mkdir -p build \
 && for d in src dist; do \
      if [ -d "$d" ]; then \
        mv "$d"/* build/; \
      fi; \
    done

FROM node:23.11.0-slim

LABEL "maintainer"="support@acuvity.ai"
LABEL "mcp-server-scope"="native"

LABEL org.opencontainers.image.title="mcp-server-nuclei"
LABEL org.opencontainers.image.description="Template-based vulnerability scanner using Nuclei's extensive library of security checks"
LABEL org.opencontainers.image.version="6190e55"
LABEL org.opencontainers.image.source="https://github.com/cyproxio/mcp-for-security/tree/HEAD/nuclei-mcp"
LABEL org.opencontainers.image.licenses="MIT License"
LABEL org.opencontainers.image.author="cyproxio"
LABEL org.opencontainers.image.created="2006-01-02T15:04:05Z07:00"

WORKDIR /app

ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN apt-get update \
    && apt-get install -y curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=artifacts /tmp/binaries /usr/local/bin

HEALTHCHECK CMD curl --fail http://localhost:8080 || exit 1

RUN groupadd -r -g 1001 appuser && \
    useradd -r -u 1001 -g appuser -m appuser && \
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
