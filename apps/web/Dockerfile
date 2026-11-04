# Multi-stage production build for KELVIN Frontend Application
# Stage 1: Build Web App
FROM node:20-alpine AS builder

WORKDIR /app

# Copy root workspace configurations
COPY package.json package-lock.json* ./
COPY apps/web/package.json ./apps/web/
COPY packages/common/package.json* ./packages/common/
COPY packages/schemas/package.json* ./packages/schemas/

# Install dependencies
RUN npm install

# Copy source trees
COPY packages/ ./packages/
COPY apps/web/ ./apps/web/

# Build static assets under /services/kelvin/
ENV VITE_BASE_PATH=/services/kelvin/
RUN npm --prefix apps/web run build

# Stage 2: Production Nginx Server
FROM nginx:1.27-alpine AS runner

# Remove default nginx static assets
RUN rm -rf /usr/share/nginx/html/*

# Copy build artifacts to /services/kelvin/ directory
COPY --from=builder /app/apps/web/dist /usr/share/nginx/html/services/kelvin

# Copy custom Nginx configuration
COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf

# Security: run as unprivileged user if desired, or default nginx
EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
