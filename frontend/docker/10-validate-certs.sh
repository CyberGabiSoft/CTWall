#!/bin/sh
set -eu

cert_path="${FRONTEND_SSL_CERT_PATH:-/etc/nginx/certs/tls.crt}"
key_path="${FRONTEND_SSL_KEY_PATH:-/etc/nginx/certs/tls.key}"

if [ ! -f "${cert_path}" ]; then
  echo "ERROR: TLS certificate file not found: ${cert_path}" >&2
  echo "Provide certificate by mounting file and setting FRONTEND_SSL_CERT_PATH." >&2
  exit 1
fi

if [ ! -f "${key_path}" ]; then
  echo "ERROR: TLS private key file not found: ${key_path}" >&2
  echo "Provide key by mounting file and setting FRONTEND_SSL_KEY_PATH." >&2
  exit 1
fi

