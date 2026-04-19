#!/bin/bash
set -euo pipefail

DUMP_FILE="/docker-entrypoint-initdb.d/nutrients.dump"
DB_NAME="nutrients"

echo "Restoring ${DB_NAME} database from dump..."

# Create the database if it doesn't exist
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    SELECT 'CREATE DATABASE ${DB_NAME}'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${DB_NAME}')\gexec
EOSQL

# Detect dump format and restore accordingly
if pg_restore --list "$DUMP_FILE" >/dev/null 2>&1; then
    echo "Detected pg_dump custom/tar/directory format. Using pg_restore..."
    pg_restore \
        -v \
        --username="$POSTGRES_USER" \
        --dbname="$DB_NAME" \
        --no-owner \
        --no-acl \
        "$DUMP_FILE"
else
    echo "Detected plain SQL dump. Using psql..."
    psql \
        -v ON_ERROR_STOP=1 \
        --username="$POSTGRES_USER" \
        --dbname="$DB_NAME" \
        -f "$DUMP_FILE"
fi

echo "Nutrients database restored successfully!"
