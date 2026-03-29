# syntax=docker/dockerfile:1.7

FROM node:25-alpine AS builder
WORKDIR /workspace

COPY src/package.json src/package-lock.json ./
RUN npm ci

COPY src/ ./
RUN npm run build

FROM nginx:1.28-alpine

RUN apk add --no-cache openssl && \
    rm -f /etc/nginx/conf.d/default.conf && \
    mkdir -p /etc/nginx/certs /etc/nginx/templates /run && \
    chown -R 101:101 /etc/nginx/conf.d /etc/nginx/templates /etc/nginx/certs /run /var/cache/nginx /var/log/nginx

COPY docker/nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --chmod=755 docker/05-ensure-certs.sh docker/10-validate-certs.sh /docker-entrypoint.d/
COPY --from=builder /workspace/dist/ctwall/browser /usr/share/nginx/html

# Override at runtime when backend runs under a different host/port.
ENV BACKEND_UPSTREAM=http://127.0.0.1:8080 \
    FRONTEND_HTTP_PORT=8080 \
    FRONTEND_SSL_PORT=443 \
    FRONTEND_SSL_CERT_PATH=/etc/nginx/certs/tls.crt \
    FRONTEND_SSL_KEY_PATH=/etc/nginx/certs/tls.key \
    FRONTEND_SSL_AUTO_GENERATE=true \
    FRONTEND_SSL_SELF_SIGNED_CN=localhost \
    FRONTEND_SSL_SELF_SIGNED_DAYS=365

EXPOSE 8080 443
