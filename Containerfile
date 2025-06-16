# Stage 1: Build the Vue.js frontend
FROM node:23 AS frontend-builder

COPY assets/*.png /app/assets/

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN --mount=type=cache,target=/root/.npm npm install

COPY frontend/ ./
RUN npm run build

# Stage 2: Build the Rust backend
FROM rust:1.87 AS backend-builder

WORKDIR /app/backend
COPY backend/ ./
RUN --mount=type=cache,target=/app/backend/target \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    cargo build --release && cp target/release/backend backend

# Stage 3: Final container with Nginx and the backend binary
FROM docker.io/nginx:stable


WORKDIR /app/data
COPY --from=frontend-builder /app/frontend/dist/ /usr/share/nginx/html/
COPY container/nginx.conf /etc/nginx/nginx.conf
COPY --from=backend-builder /app/backend/backend /app/bin/backend

# Expose port 80 for HTTP
EXPOSE 80

# Start both Nginx and the backend server
CMD ["/bin/sh", "-c", "nginx && /app/bin/backend"]