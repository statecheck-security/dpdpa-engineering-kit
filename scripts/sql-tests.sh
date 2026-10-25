#!/usr/bin/env bash
# Loads each schema into a fresh PostgreSQL database and runs its behaviour test.
# Uses the standard PG* environment variables (PGHOST, PGUSER, PGPASSWORD, ...).
# PSQL can point at another client, e.g. PSQL="docker exec -i kitpg psql -U postgres".
set -euo pipefail
cd "$(dirname "$0")/.."

PSQL=${PSQL:-psql}

# name | setup (optional) | schema | test
SUITES=(
  "consent|              |consent/schema.sql                 |consent/tests/schema_test.sql"
  "consent_soc2|consent/tests/soc2_audit_log_setup.sql|consent/soc2-consent-audit-log.sql|consent/tests/soc2_audit_log_test.sql"
  "consent_manager|      |consent-manager/ledger.sql         |consent-manager/tests/ledger_test.sql"
  "roadmap_consent|      |governance/consent-record.sql      |governance/tests/consent_record_test.sql"
)

trim() { local s=$1; s=${s#"${s%%[![:space:]]*}"}; echo "${s%"${s##*[![:space:]]}"}"; }

failed=0
for suite in "${SUITES[@]}"; do
  IFS='|' read -r name setup schema test <<<"$suite"
  name=$(trim "$name"); setup=$(trim "$setup"); schema=$(trim "$schema"); test=$(trim "$test")
  db="kit_${name}"
  $PSQL -q -v ON_ERROR_STOP=1 -d postgres -c "DROP DATABASE IF EXISTS ${db}" -c "CREATE DATABASE ${db}" >/dev/null
  if cat ${setup:+"$setup"} "$schema" "$test" | $PSQL -q -v ON_ERROR_STOP=1 -d "$db" >/dev/null; then
    echo "ok    ${name}"
  else
    echo "FAIL  ${name}"
    failed=1
  fi
done
exit $failed
