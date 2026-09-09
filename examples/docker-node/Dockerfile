FROM node:22-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --chmod=755 keevault /usr/local/bin/keevault
COPY server.mjs keevault.json ./
USER node
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/keevault"]
