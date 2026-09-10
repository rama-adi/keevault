FROM debian:bookworm-slim AS keevault-download
ARG KEEVAULT_VER=latest
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /download
RUN curl -fsSL https://vault.keevault.my.id/download.sh -o download.sh \
    && KEEVAULT_VER="$KEEVAULT_VER" sh download.sh

FROM node:22-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=keevault-download /download/keevault /usr/local/bin/keevault
COPY server.mjs keevault.json ./
USER node
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/keevault"]
