# Build context is the repository root. See README.md for required build args.
FROM --platform=$BUILDPLATFORM alpine:3.22 AS download
ARG TARGETARCH
ARG KEEVAULT_RELEASE_URL
ARG KEEVAULT_VERSION
ARG KEEVAULT_SHA256_AMD64
ARG KEEVAULT_SHA256_ARM64
RUN apk add --no-cache curl ca-certificates
RUN set -eu; \
    case "$KEEVAULT_RELEASE_URL" in https://*) ;; *) echo 'KEEVAULT_RELEASE_URL must use HTTPS' >&2; exit 1;; esac; \
    echo "$KEEVAULT_VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$'; \
    case "$TARGETARCH" in \
      amd64) checksum="$KEEVAULT_SHA256_AMD64" ;; \
      arm64) checksum="$KEEVAULT_SHA256_ARM64" ;; \
      *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    echo "$checksum" | grep -Eq '^[a-fA-F0-9]{64}$'; \
    curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
      --retry 3 --connect-timeout 10 --max-time 120 \
      "${KEEVAULT_RELEASE_URL%/}/releases/${KEEVAULT_VERSION}/keevault-linux-${TARGETARCH}" -o /keevault; \
    echo "$checksum  /keevault" | sha256sum -c -; \
    chmod 0755 /keevault

FROM node:22-alpine
WORKDIR /app
COPY --from=download /keevault /usr/local/bin/keevault
COPY examples/zeabur-node-app/package.json examples/zeabur-node-app/server.js examples/zeabur-node-app/keevault.json ./
EXPOSE 3000
# The server starts after approval, so it cannot report healthy while waiting.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O- http://127.0.0.1:3000/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/keevault"]
