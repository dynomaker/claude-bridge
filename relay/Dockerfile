# Build from the repository root: docker build -f relay/Dockerfile -t claude-bridge-relay .
FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json tsconfig.json ./
COPY packages/core/package.json packages/core/
COPY relay/package.json relay/
RUN npm ci
COPY packages/core packages/core
COPY relay relay
RUN npx tsc -b relay

FROM node:22-slim
ENV NODE_ENV=production PORT=8787 DB_PATH=/data/relay.db
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/
COPY relay/package.json relay/
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/packages/core/dist packages/core/dist
COPY --from=build /app/relay/dist relay/dist
RUN mkdir /data && chown node:node /data
USER node
VOLUME /data
EXPOSE 8787
CMD ["node", "relay/dist/main.js"]
