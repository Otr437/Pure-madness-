# ================ ZEC ARENA PRODUCTION DOCKERFILE ================
# 
# Node 18 LTS Alpine → smallest & most secure base
FROM node:18-alpine AS base

# Install dumb-init (proper signal handling + zombie reaping)
RUN apk add --no-cache dumb-init

WORKDIR /app

# ================ DEPENDENCIES STAGE ================
FROM base AS deps

# Install ALL deps first (for better layer caching)
COPY package*.json ./
RUN npm ci --include=dev

# ================ BUILD STAGE (if you ever add build step) ================
FROM deps AS build
# (Currently no build step – pure runtime)

# ================ PRODUCTION IMAGE ================
FROM base AS production

# Copy node_modules from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy source code
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 && \
    chown -R nodejs:nodejs /app

USER nodejs

# Expose port (matches your CONFIG.PORT fallback)
EXPOSE 3001

# Health check – your backend has /health
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3001/health || exit 1

# Use dumb-init to forward signals correctly (very important for graceful shutdown)
ENTRYPOINT ["dumb-init", "--"]

# Start command
CMD ["node", "backend.js"]