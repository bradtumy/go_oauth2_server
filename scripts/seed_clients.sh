#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLIENTS_DIR="${CLIENTS_DIR:-${ROOT_DIR}/clients}"
AS_CLIENTS_DB="${AS_CLIENTS_DB:-${ROOT_DIR}/data/clients.db}"

mkdir -p "$(dirname "${AS_CLIENTS_DB}")"

go run ./cmd/seed-clients -db "${AS_CLIENTS_DB}" -dir "${CLIENTS_DIR}"
