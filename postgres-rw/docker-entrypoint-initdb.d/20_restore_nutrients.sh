#!/bin/bash
set -e

echo "Restoring nutrients database from dump..."

# Create the nutrients database if it doesn't exist
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    SELECT 'CREATE DATABASE nutrients'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'nutrients')\gexec
EOSQL

# Restore the dump file into the nutrients database
pg_restore -v --username="$POSTGRES_USER" --dbname=nutrients --no-owner --no-acl /docker-entrypoint-initdb.d/nutrients.dump

echo "Nutrients database restored successfully!"
