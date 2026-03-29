#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_SRC_DIR="${ROOT_DIR}/backend/src"

NAMESPACE="${NAMESPACE:-ctwall}"
HELM_RELEASE="${HELM_RELEASE:-ctwall}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@ctwall}"
KUBECTL_CMD_RAW="${KUBECTL:-kubectl}"

read -r -a KUBECTL_CMD <<<"${KUBECTL_CMD_RAW}"

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

k() {
  "${KUBECTL_CMD[@]}" "$@"
}

sql_escape() {
  printf "%s" "$1" | sed "s/'/''/g"
}

get_backend_pod() {
  local pod
  pod="$(k -n "${NAMESPACE}" get pod \
    -l "app.kubernetes.io/instance=${HELM_RELEASE},app.kubernetes.io/name=backend" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  if [[ -z "${pod}" ]]; then
    pod="$(k -n "${NAMESPACE}" get pod -l "app.kubernetes.io/name=backend" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  fi
  printf "%s" "${pod}"
}

get_postgres_pod() {
  local pod="${HELM_RELEASE}-postgresql-0"
  if k -n "${NAMESPACE}" get pod "${pod}" >/dev/null 2>&1; then
    printf "%s" "${pod}"
    return
  fi
  pod="$(k -n "${NAMESPACE}" get pod \
    -l "app.kubernetes.io/instance=${HELM_RELEASE},app.kubernetes.io/name=postgresql,app.kubernetes.io/component=primary" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  printf "%s" "${pod}"
}

get_db_url_from_backend_deploy() {
  k -n "${NAMESPACE}" get deploy "${HELM_RELEASE}-backend" -o jsonpath='{range .spec.template.spec.containers[?(@.name=="backend")].env[?(@.name=="DB_URL")]}{.value}{end}' 2>/dev/null || true
}

debug_read_backend_file() {
  local backend_pod="$1"
  local file_path="$2"
  local ec_name="read-admin-creds-$(date +%s)"
  local out=""

  k -n "${NAMESPACE}" debug "${backend_pod}" \
    --profile=restricted \
    --target=backend \
    --image=busybox:1.36 \
    -c "${ec_name}" \
    --quiet \
    -- cat "/proc/1/root${file_path}" >/dev/null

  for _ in $(seq 1 20); do
    out="$(k -n "${NAMESPACE}" logs "${backend_pod}" -c "${ec_name}" --tail=200 2>/dev/null || true)"
    if [[ -n "${out}" ]]; then
      printf "%s\n" "${out}"
      return 0
    fi
    sleep 1
  done

  return 1
}

debug_write_backend_file_b64() {
  local backend_pod="$1"
  local file_path="$2"
  local payload_b64="$3"
  local ec_name="write-admin-creds-$(date +%s)"

  k -n "${NAMESPACE}" debug "${backend_pod}" \
    --profile=restricted \
    --target=backend \
    --image=busybox:1.36 \
    -c "${ec_name}" \
    --quiet \
    -- sh -lc "umask 077; echo '${payload_b64}' | base64 -d > '/proc/1/root${file_path}'; chmod 600 '/proc/1/root${file_path}'"
}

require_cmd "${KUBECTL_CMD[0]}"
require_cmd go
require_file "${BACKEND_SRC_DIR}/go.mod"

BACKEND_POD="$(get_backend_pod)"
if [[ -z "${BACKEND_POD}" ]]; then
  echo "Could not find backend pod in namespace ${NAMESPACE} (release=${HELM_RELEASE})." >&2
  exit 1
fi

POSTGRES_POD="$(get_postgres_pod)"
if [[ -z "${POSTGRES_POD}" ]]; then
  echo "Could not find PostgreSQL pod in namespace ${NAMESPACE} (release=${HELM_RELEASE})." >&2
  exit 1
fi

echo "[1/7] Waiting for backend/postgresql pods to be Ready..."
k -n "${NAMESPACE}" wait --for=condition=Ready "pod/${BACKEND_POD}" --timeout=180s >/dev/null
k -n "${NAMESPACE}" wait --for=condition=Ready "pod/${POSTGRES_POD}" --timeout=180s >/dev/null

echo "[2/7] Resolving DB connection settings..."
DB_URL="${DB_URL:-$(get_db_url_from_backend_deploy)}"
if [[ -z "${DB_URL}" ]]; then
  echo "DB_URL could not be resolved from backend deployment. Set DB_URL/POSTGRES_* envs explicitly." >&2
  exit 1
fi

POSTGRES_USER="${POSTGRES_USER:-$(printf "%s" "${DB_URL}" | sed -n 's#^postgres://\([^:/?]*\):.*#\1#p')}"
POSTGRES_DB="${POSTGRES_DB:-$(printf "%s" "${DB_URL}" | sed -n 's#^.*/\([^/?]*\)\(\?.*\)\?$#\1#p')}"

if [[ -z "${POSTGRES_USER}" || -z "${POSTGRES_DB}" ]]; then
  echo "Failed to parse POSTGRES_USER/POSTGRES_DB from DB_URL. Set POSTGRES_USER and POSTGRES_DB explicitly." >&2
  exit 1
fi

POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"
if [[ -z "${POSTGRES_PASSWORD}" ]] && k -n "${NAMESPACE}" get secret "${HELM_RELEASE}-postgresql" >/dev/null 2>&1; then
  POSTGRES_PASSWORD="$(k -n "${NAMESPACE}" get secret "${HELM_RELEASE}-postgresql" -o jsonpath='{.data.password}' | base64 -d || true)"
fi
if [[ -z "${POSTGRES_PASSWORD}" ]]; then
  POSTGRES_PASSWORD="$(printf "%s" "${DB_URL}" | sed -n 's#^postgres://[^:]*:\([^@]*\)@.*#\1#p')"
fi
if [[ -z "${POSTGRES_PASSWORD}" ]]; then
  echo "Failed to resolve PostgreSQL password. Set POSTGRES_PASSWORD explicitly." >&2
  exit 1
fi

AUTH_PEPPER="$(k -n "${NAMESPACE}" get deploy "${HELM_RELEASE}-backend" -o jsonpath='{range .spec.template.spec.containers[?(@.name=="backend")].env[?(@.name=="AUTH_PEPPER")]}{.value}{end}' 2>/dev/null || true)"

ADMIN_EMAIL_SQL="$(sql_escape "${ADMIN_EMAIL}")"

echo "[3/7] Verifying admin user exists..."
ADMIN_EXISTS="$(
  k -n "${NAMESPACE}" exec "${POSTGRES_POD}" -- env PGPASSWORD="${POSTGRES_PASSWORD}" \
    psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -tA -c \
    "SELECT COUNT(*) FROM users WHERE email='${ADMIN_EMAIL_SQL}';" | tr -d '[:space:]'
)"
if [[ "${ADMIN_EXISTS}" != "1" ]]; then
  echo "Admin user ${ADMIN_EMAIL} was not found in database ${POSTGRES_DB}." >&2
  exit 1
fi

echo "[4/7] Generating new admin password and Argon2id hash..."
TMP_GO="$(mktemp "${BACKEND_SRC_DIR}/tmp-reset-admin-hash-k8s-XXXXXX.go")"
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

echo "[5/7] Updating admin password hash directly in PostgreSQL..."
ADMIN_HASH_SQL="$(sql_escape "${ADMIN_HASH}")"
UPDATE_OUT="$(
  k -n "${NAMESPACE}" exec "${POSTGRES_POD}" -- env PGPASSWORD="${POSTGRES_PASSWORD}" \
    psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -v ON_ERROR_STOP=1 -tA -c \
    "UPDATE users SET password_hash='${ADMIN_HASH_SQL}', updated_at=NOW() WHERE email='${ADMIN_EMAIL_SQL}' RETURNING id;"
)"
if [[ -z "$(echo "${UPDATE_OUT}" | tr -d '[:space:]')" ]]; then
  echo "Password hash update failed (no row returned)." >&2
  exit 1
fi

echo "[6/7] Writing refreshed /app/data/bootstrap-admin-credentials.json ..."
CREDENTIALS_JSON="$(printf '{\n  "email": "%s",\n  "password": "%s"\n}\n' "${ADMIN_EMAIL}" "${ADMIN_PASSWORD}")"
CREDENTIALS_B64="$(printf "%s" "${CREDENTIALS_JSON}" | base64 | tr -d '\n')"
debug_write_backend_file_b64 "${BACKEND_POD}" "/app/data/bootstrap-admin-credentials.json" "${CREDENTIALS_B64}"

echo "[7/7] Verifying credentials file write..."
RAW_CREDS="$(debug_read_backend_file "${BACKEND_POD}" "/app/data/bootstrap-admin-credentials.json")"
if [[ -z "${RAW_CREDS}" ]]; then
  echo "Credentials file verification failed." >&2
  exit 1
fi

echo
echo "Admin password reset completed (Helm/Kubernetes mode, no migrations executed)."
echo "namespace: ${NAMESPACE}"
echo "release: ${HELM_RELEASE}"
echo "email: ${ADMIN_EMAIL}"
echo "password: ${ADMIN_PASSWORD}"
echo
echo "Raw credentials file:"
echo "${RAW_CREDS}"
