FROM node:20-alpine AS base
WORKDIR /app
COPY package.json package-lock.json ./
COPY apps/identity-gateway/package.json apps/identity-gateway/package.json
COPY packages/auth/package.json packages/auth/package.json
COPY packages/config/package.json packages/config/package.json
COPY packages/crypto/package.json packages/crypto/package.json
COPY packages/db/package.json packages/db/package.json
COPY packages/http/package.json packages/http/package.json
COPY packages/observability/package.json packages/observability/package.json
COPY packages/types/package.json packages/types/package.json
RUN npm ci
COPY . .
RUN npm run build -- --filter=@verza/identity-gateway...

FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=base /app/node_modules /app/node_modules
COPY --from=base /app/apps/identity-gateway/dist /app/dist
COPY --from=base /app/packages /app/packages
CMD ["node", "/app/dist/index.js"]
