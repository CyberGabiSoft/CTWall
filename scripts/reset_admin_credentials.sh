#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="${ROOT_DIR}/deploy/docker"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"
ENV_FILE="${DEPLOY_DIR}/.env"
BACKEND_SRC_DIR="${ROOT_DIR}/backend/src"

POSTGRES_CONTAINER="ctwall-postgres"
BACKEND_DATA_VOLUME="ctwall_ctwall-backend-data"
CREDENTIALS_PATH="/data/bootstrap-admin-credentials.json"
ADMIN_EMAIL="admin@ctwall"

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required command: ${cmd}" >&2
    exit 1
  fi
}

require_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    echo "Missing required file: ${path}" >&2
    exit 1
  fi
}

compose() {
  docker compose \
    -f "${COMPOSE_FILE}" \
    --project-directory "${ROOT_DIR}" \
    --env-file "${ENV_FILE}" \
    "$@"
}

wait_postgres_healthy() {
  local retries=60
  local status=""
  for _ in $(seq 1 "${retries}"); do
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${POSTGRES_CONTAINER}" 2>/dev/null || true)"
    if [[ "${status}" == "healthy" ]]; then
      return 0
    fi
    sleep 2
  done
  echo "PostgreSQL did not become healthy (last status: ${status:-unknown})." >&2
  docker logs --tail 80 "${POSTGRES_CONTAINER}" >&2 || true
  exit 1
}

require_cmd docker
require_cmd go
require_file "${COMPOSE_FILE}"
require_file "${ENV_FILE}"
require_file "${BACKEND_SRC_DIR}/go.mod"

# shellcheck disable=SC1090
source "${ENV_FILE}"

POSTGRES_DB="${POSTGRES_DB:-appdb}"
POSTGRES_USER="${POSTGRES_USER:-appuser}"

AUTH_PEPPER="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' ctwall-backend 2>/dev/null | sed -n 's/^AUTH_PEPPER=//p' | head -n1)"
AUTH_PEPPER="${AUTH_PEPPER:-}"

echo "[1/6] Ensuring PostgreSQL is running..."
compose up -d ctwall-postgres >/dev/null
wait_postgres_healthy

echo "[2/6] Verifying admin user exists..."
ADMIN_EXISTS="$(
  docker exec "${POSTGRES_CONTAINER}" psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -tA -c \
    "SELECT COUNT(*) FROM users WHERE email='${ADMIN_EMAIL}';" | tr -d '[:space:]'
)"
if [[ "${ADMIN_EXISTS}" != "1" ]]; then
  echo "Admin user ${ADMIN_EMAIL} was not found in database ${POSTGRES_DB}." >&2
  exit 1
fi

echo "[3/6] Generating new admin password and Argon2id hash..."
TMP_GO="$(mktemp "${BACKEND_SRC_DIR}/tmp-reset-admin-hash-XXXXXX.go")"
cleanup_tmp_go() {
  rm -f "${TMP_GO}"
}
trap cleanup_tmp_go EXIT
cat > "${TMP_GO}" <<'EOF'
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 2
	argonKeyLen  uint32 = 32
)

func mustRandom(size int) []byte {
	out := make([]byte, size)
	if _, err := rand.Read(out); err != nil {
		panic(err)
	}
	return out
}

func main() {
	password := base64.RawURLEncoding.EncodeToString(mustRandom(24))
	pepper := os.Getenv("AUTH_PEPPER")
	passwordForHash := password
	if pepper != "" {
		passwordForHash = passwordForHash + ":" + pepper
	}

	salt := mustRandom(16)
	hash := argon2.IDKey([]byte(passwordForHash), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)
	fullHash := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads, encodedSalt, encodedHash)

	fmt.Printf("PASSWORD=%s\n", password)
	fmt.Printf("HASH=%s\n", fullHash)
}
EOF

GEN_OUT="$(cd "${BACKEND_SRC_DIR}" && AUTH_PEPPER="${AUTH_PEPPER}" go run "${TMP_GO}")"
ADMIN_PASSWORD="$(printf '%s\n' "${GEN_OUT}" | sed -n 's/^PASSWORD=//p' | head -n1)"
ADMIN_HASH="$(printf '%s\n' "${GEN_OUT}" | sed -n 's/^HASH=//p' | head -n1)"
if [[ -z "${ADMIN_PASSWORD}" || -z "${ADMIN_HASH}" ]]; then
  echo "Failed to generate password/hash." >&2
  exit 1
fi

echo "[4/6] Updating admin password hash directly in PostgreSQL..."
UPDATE_OUT="$(
  docker exec "${POSTGRES_CONTAINER}" psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -tA -c \
    "UPDATE users SET password_hash='${ADMIN_HASH}', updated_at=NOW() WHERE email='${ADMIN_EMAIL}' RETURNING id;"
)"
if [[ -z "$(echo "${UPDATE_OUT}" | tr -d '[:space:]')" ]]; then
  echo "Password hash update failed (no row returned)." >&2
  exit 1
fi

echo "[5/6] Writing refreshed bootstrap credentials file..."
docker volume inspect "${BACKEND_DATA_VOLUME}" >/dev/null 2>&1 || docker volume create "${BACKEND_DATA_VOLUME}" >/dev/null
printf '{\n  "email": "%s",\n  "password": "%s"\n}\n' "${ADMIN_EMAIL}" "${ADMIN_PASSWORD}" | \
  docker run --rm -i -v "${BACKEND_DATA_VOLUME}:/data" busybox sh -c \
    "cat > ${CREDENTIALS_PATH} && chmod 600 ${CREDENTIALS_PATH}"

echo "[6/6] Done."
echo
echo "Admin password reset completed (no initializer/migrations executed)."
echo "email: ${ADMIN_EMAIL}"
echo "password: ${ADMIN_PASSWORD}"
echo
echo "Login URL: https://127.0.0.1:8443"
echo
echo "Raw credentials file:"
docker run --rm -v "${BACKEND_DATA_VOLUME}:/data" busybox cat "${CREDENTIALS_PATH}"
