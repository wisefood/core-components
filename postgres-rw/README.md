# PostgreSQL with Nutrients Database

This directory contains a PostgreSQL image with the nutrients database pre-loaded from a dump file.

## Building the Image

```bash
docker build -t wisefood/postgres-nutrients:latest .
```

Or using the Makefile:

```bash
make build
```

## Running the Container

```bash
docker run -d \
  --name postgres-nutrients \
  -e POSTGRES_PASSWORD=your_password \
  -p 5432:5432 \
  wisefood/postgres-nutrients:latest
```

## Database Details

- **Database Name**: `nutrients`
- **Default Port**: 5432
- **Dump File**: `nutrients.dump` (PostgreSQL custom format)

## Notes

- The nutrients database is automatically restored on first container startup
- The dump file is restored using `pg_restore` with `--no-owner` and `--no-acl` flags for portability
- Initialization scripts run in alphabetical order (20_restore_nutrients.sh)
