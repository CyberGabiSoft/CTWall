#!/bin/sh
set -eu

cert_path="${FRONTEND_SSL_CERT_PATH:-/etc/nginx/certs/tls.crt}"
key_path="${FRONTEND_SSL_KEY_PATH:-/etc/nginx/certs/tls.key}"
auto_generate="${FRONTEND_SSL_AUTO_GENERATE:-true}"
common_name="${FRONTEND_SSL_SELF_SIGNED_CN:-localhost}"
valid_days="${FRONTEND_SSL_SELF_SIGNED_DAYS:-365}"

is_enabled() {
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "${value}" in
    1|true|yes|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

if [ -f "${cert_path}" ] && [ -f "${key_path}" ]; then
  exit 0
fi

if ! is_enabled "${auto_generate}"; then
  echo "TLS files are missing and FRONTEND_SSL_AUTO_GENERATE is disabled." >&2
  echo "Provide cert/key files or generate locally with src/frontend/docker/generate_selfsigned.sh." >&2
  exit 1
fi

cert_dir="$(dirname "${cert_path}")"
key_dir="$(dirname "${key_path}")"
mkdir -p "${cert_dir}" "${key_dir}"

echo "TLS files missing. Generating self-signed certificate for CN=${common_name} (${valid_days} days)."
openssl req \
  -x509 \
  -newkey rsa:2048 \
  -sha256 \
  -days "${valid_days}" \
  -nodes \
  -subj "/CN=${common_name}" \
  -addext "subjectAltName=DNS:${common_name},IP:127.0.0.1" \
  -keyout "${key_path}" \
  -out "${cert_path}"

chmod 600 "${key_path}"
chmod 644 "${cert_path}"
