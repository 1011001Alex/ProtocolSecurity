# =============================================================================
# Protocol Security - Production Docker Image
# Created by Theodor Munch
# Copyright (c) 2026 Theodor Munch. All rights reserved.
# =============================================================================

# =============================================================================
# Stage 1: Dependencies
# =============================================================================
FROM node:18-alpine AS deps

RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install all dependencies (including dev for build)
RUN npm ci

# =============================================================================
# Stage 2: Build
# =============================================================================
FROM node:18-alpine AS builder

RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy dependencies from deps stage
COPY --from=deps /app/node_modules ./node_modules
COPY package*.json ./
COPY tsconfig.json ./
COPY src ./src
COPY scripts ./scripts
COPY jest.config.js ./

# Build TypeScript
RUN npm run build

# Run tests
RUN npm test -- --coverage

# =============================================================================
# Stage 3: Production
# =============================================================================
FROM node:18-alpine AS production

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# Copy built application from builder stage
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/scripts ./scripts

# Copy documentation
COPY README.md ./

# Change ownership to non-root user
RUN chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node dist/healthcheck.js || exit 1

# Start application
CMD ["node", "dist/index.js"]

# =============================================================================
# Stage 4: Development
# =============================================================================
FROM node:18-alpine AS development

RUN apk add --no-cache python3 make g++ git

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install all dependencies
RUN npm ci

# Copy source code
COPY src ./src
COPY scripts ./scripts
COPY jest.config.js ./
COPY .env.example .env

# Expose port
EXPOSE 3000

# Enable nodemon
ENV NODE_ENV=development

CMD ["npm", "run", "dev"]
