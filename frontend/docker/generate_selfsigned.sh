#!/usr/bin/env bash
# Usage:
#   ./generate_selfsigned.sh [OUTPUT_DIR] [COMMON_NAME] [DAYS]
# Example:
#   ./generate_selfsigned.sh ./certs localhost 365

OUTPUT_DIR="${1:-./certs}"
COMMON_NAME="${2:-localhost}"
DAYS="${3:-365}"

CRT_PATH="${OUTPUT_DIR}/tls.crt"
KEY_PATH="${OUTPUT_DIR}/tls.key"

mkdir -p "${OUTPUT_DIR}"

TMP_CFG="$(mktemp)"
cleanup() { rm -f "${TMP_CFG}"; }
trap cleanup EXIT

cat > "${TMP_CFG}" <<EOF
[ req ]
default_bits       = 4096
prompt             = no
default_md         = sha256
x509_extensions    = v3_req
distinguished_name = dn

[ dn ]
CN = ${COMMON_NAME}

[ v3_req ]
subjectAltName = @alt_names
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ alt_names ]
DNS.1 = ${COMMON_NAME}
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl req \
  -x509 \
  -nodes \
  -newkey rsa:4096 \
  -days "${DAYS}" \
  -keyout "${KEY_PATH}" \
  -out "${CRT_PATH}" \
  -config "${TMP_CFG}"

chmod 600 "${KEY_PATH}"
chmod 644 "${CRT_PATH}"

echo "Self-signed TLS certificate generated:"
echo "  CERT: ${CRT_PATH}"
echo "  KEY : ${KEY_PATH}"
echo
MOUNT_SRC="${OUTPUT_DIR}"
if [[ "${OUTPUT_DIR}" != /* ]]; then
  MOUNT_SRC="\$(pwd)/${OUTPUT_DIR}"
fi

echo "Example docker run:"
echo "  docker run --rm -p 443:443 \\"
echo "    -v \"${MOUNT_SRC}:/etc/nginx/certs:ro\" \\"
echo "    -e FRONTEND_SSL_CERT_PATH=/etc/nginx/certs/tls.crt \\"
echo "    -e FRONTEND_SSL_KEY_PATH=/etc/nginx/certs/tls.key \\"
echo "    ctwall-frontend:local"
