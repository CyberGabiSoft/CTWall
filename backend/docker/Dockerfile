# syntax=docker/dockerfile:1.7

FROM golang:1.25.8-alpine AS builder
WORKDIR /workspace

COPY src/go.mod src/go.sum ./
RUN go mod download

COPY src ./
RUN mkdir -p /rootfs/usr/local/bin /rootfs/app/data/blob_storage /rootfs/app/src/migrations /rootfs/alertmanager /rootfs/app/config && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -buildid=" -o /rootfs/usr/local/bin/ctwall-backend ./cmd/server && \
    cp -r /workspace/migrations/. /rootfs/app/src/migrations/ && \
    touch /rootfs/app/config/.keep
COPY config.yaml /rootfs/app/config.template.yaml

FROM gcr.io/distroless/static-debian13:nonroot
WORKDIR /app

COPY --from=builder --chown=65532:65532 /rootfs/ /

ENV CTWALL_CONFIG_PATH=/app/config/config.yaml \
    CTWALL_CONFIG_TEMPLATE_PATH=/app/config.template.yaml \
    CTWALL_SECRETS_PATH=/app/config/secrets.yaml \
    ALERTMANAGER_CONFIG_FILE_PATH=/app/config/alertmanager.yml

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/ctwall-backend"]
