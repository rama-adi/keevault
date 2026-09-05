# Build context is the repository root:
#   docker build -f examples/zeabur-node-app/Dockerfile .
#
# Stage 1 builds vault-bootstrap from apps/env-client, statically, for the
# target architecture. Stage 2 is the actual runtime image: Node 22 plus the
# vault-bootstrap binary as the entrypoint. No secret ever goes into either
# stage; VAULT_URL and VAULT_BOOTSTRAP_TOKEN are Zeabur environment variables
# supplied at deploy time, not build args and not baked into the image.

FROM golang:1.26-alpine AS build
ARG TARGETARCH
WORKDIR /src
COPY apps/env-client/ apps/env-client/
WORKDIR /src/apps/env-client
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w" -o /out/vault-bootstrap .

FROM node:22-alpine
WORKDIR /app
COPY --from=build /out/vault-bootstrap /usr/local/bin/vault-bootstrap
COPY examples/zeabur-node-app/package.json examples/zeabur-node-app/server.js ./

EXPOSE 3000

# This healthcheck only tells Docker/Zeabur whether the process that is
# currently running answers on /healthz. It does not, and must not, report
# ready before vault-bootstrap has received an approved boot: node only
# starts after vault-bootstrap execs into it, so there is nothing to answer
# until that happens. See docs/zeabur.md for the readiness caveat.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O- http://127.0.0.1:3000/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/vault-bootstrap", "--"]
CMD ["node", "server.js"]
