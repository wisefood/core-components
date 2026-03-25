FROM python:3.13-slim

WORKDIR /app

COPY . /app/

ENV ES_URL=http://localhost:9200 \
    INDEX_NAME=recipes \
    IMPORT_FILE=/app/recipes_dump.json \
    SCHEMA_FILE=/app/recipes_schema.json \
    DELETE_INDEX=true \
    BATCH_SIZE=1000 \
    REQUEST_TIMEOUT=120 \
    LOG_EVERY=5000 \
    LOG_DIR=/app/logs

CMD ["python3", "import.py"]
