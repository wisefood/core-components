FROM python:3.13-slim

WORKDIR /app

# The handoff bundle is ~600MB and changes far less often than the scripts, so
# it gets its own layer ahead of the code to keep rebuilds cheap.
COPY bundle/ /app/bundle/

# import.py (load one index from JSON) and dump.py (scroll one index back out)
# are kept for ad-hoc work. The stale recipes*_schema.json files are
# deliberately NOT shipped -- bundle/elasticsearch/*_mapping.json is now the
# authoritative schema, and shipping both invites loading the older one.
COPY restore.py import.py dump.py /app/

# restore.py only ever writes the indices named in the bundle manifest
# (recipes_v4_no_heuristic_cost_20260825, ingredient_vectors_v1) plus anything
# in DROP_INDICES. Everything else in the target cluster is left untouched. Set
# INDICES to narrow further.
#
# DROP_INDICES is empty by design. The recipe index now carries its own physical
# name, so a restore adds an index and moves the `recipes` alias onto it, leaving
# the previously live index as the rollback -- there is nothing to retire in the
# same pass, and naming the alias here cannot work anyway (ES refuses a
# delete-by-alias). Retire the superseded index by hand, after verifying.
ENV ES_URL=http://localhost:9200 \
    BUNDLE_DIR=/app/bundle \
    INDICES="" \
    DROP_INDICES="" \
    RECREATE_INDEX=true \
    SKIP_IF_CURRENT=false \
    VERIFY_COUNTS=true \
    NUMBER_OF_REPLICAS=0 \
    BATCH_SIZE=1000 \
    BATCH_BYTES=8388608 \
    REQUEST_TIMEOUT=300 \
    MAX_RETRIES=6 \
    LOG_EVERY=25000 \
    LOG_DIR=/app/logs \
    PYTHONUNBUFFERED=1

CMD ["python3", "restore.py"]
