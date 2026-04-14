FROM node:22-alpine AS build

RUN corepack enable && corepack prepare pnpm@10.16.1 --activate

WORKDIR /app

COPY watcher/package.json watcher/pnpm-lock.yaml watcher/pnpm-workspace.yaml ./

# Install all deps (including devDependencies for tsc)
RUN pnpm install --frozen-lockfile

COPY watcher/src ./src
COPY watcher/tsconfig.json ./
RUN pnpm exec tsc

# --- Production image ---
FROM node:22-alpine

RUN corepack enable && corepack prepare pnpm@10.16.1 --activate

WORKDIR /app

COPY watcher/package.json watcher/pnpm-lock.yaml watcher/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile --prod

COPY --from=build /app/dist ./dist

# Health check: verify heartbeat file is recent (updated each poll cycle)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "const fs=require('fs');const t=Number(fs.readFileSync('/tmp/watcher-heartbeat','utf8'));process.exit(Date.now()-t>60000?1:0)"

CMD ["node", "dist/watcher.js"]
