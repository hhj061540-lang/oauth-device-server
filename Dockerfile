FROM node:22-bookworm-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       wget \
       ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN wget -O /app/server.js \
    https://raw.githubusercontent.com/hhj061540-lang/oauth-device-server/refs/heads/main/server.js

RUN npm init -y \
    && npm install express jsonwebtoken

RUN mkdir -p /app/data

ENV NODE_ENV=production
ENV PORT=5900

EXPOSE 5900

CMD ["node", "/app/server.js"]
