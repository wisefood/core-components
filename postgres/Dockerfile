FROM postgres:17.6-alpine

# Include extra setup scripts for users, schemas and DBs.
COPY --chown=postgres:postgres docker-entrypoint-initdb.d /docker-entrypoint-initdb.d