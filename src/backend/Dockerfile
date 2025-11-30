# Use official Node.js 18 LTS (Alpine = smallest & fastest)
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package files first (best layer caching)
COPY package*.json ./

# Install ONLY production dependencies (smaller image)
RUN npm ci --only=production

# Copy the rest of your app
COPY . .

# Create non-root user for security (Render loves this)
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 && \
    chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose the port your app uses
EXPOSE 3001

# Health check – hits your /health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3001/health || exit 1

# Start the app
CMD ["npm", "start"]