FROM postgres:17.6-alpine

# Copy the nutrients dump file
COPY --chown=postgres:postgres nutrients.dump /docker-entrypoint-initdb.d/nutrients.dump

# Copy initialization script to restore the dump
COPY --chown=postgres:postgres docker-entrypoint-initdb.d /docker-entrypoint-initdb.d
