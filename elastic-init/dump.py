#!/usr/bin/env python3
"""Dump an Elasticsearch index to the NDJSON format import.py consumes.

Companion to import.py: writes <index>_dump.json (one {"_index","_id","_source"}
object per line, scroll-paginated) and <index>_schema.json (the index mappings
and a minimal settings subset, ready to be used as SCHEMA_FILE).

Usage:
    python3 dump.py --es-url http://localhost:9201 --index recipes_v2
    python3 dump.py --es-url http://localhost:9201 --index recipes_v2 \
        --out recipes_v2_dump.json --schema-out recipes_v2_schema.json

Stdlib only — runs anywhere import.py runs.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import urllib.parse
import urllib.request
from pathlib import Path

LOGGER = logging.getLogger("elastic-dump")

# Index settings worth carrying into a schema file; everything else
# (uuid, version, provided_name, creation_date) is instance-specific noise.
PORTABLE_SETTINGS = ("analysis", "number_of_shards", "number_of_replicas")


def request_json(url: str, method: str = "GET", payload: dict | None = None, timeout: int = 120):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def dump_schema(es_url: str, index: str, path: Path) -> None:
    mappings = request_json(f"{es_url}/{urllib.parse.quote(index)}/_mapping")[index]["mappings"]
    raw_settings = request_json(f"{es_url}/{urllib.parse.quote(index)}/_settings")[index]["settings"]["index"]
    settings = {k: raw_settings[k] for k in PORTABLE_SETTINGS if k in raw_settings}
    schema = {"settings": {"index": settings} if settings else {}, "mappings": mappings}
    path.write_text(json.dumps(schema, indent=2, ensure_ascii=False))
    LOGGER.info("Schema written to %s", path)


def dump_documents(es_url: str, index: str, path: Path, batch_size: int, scroll: str = "5m") -> int:
    count = 0
    page = request_json(
        f"{es_url}/{urllib.parse.quote(index)}/_search?scroll={scroll}",
        method="POST", payload={"size": batch_size, "query": {"match_all": {}}},
    )
    scroll_id = page.get("_scroll_id")
    total = page.get("hits", {}).get("total", {}).get("value", "?")

    with path.open("w", encoding="utf-8") as fh:
        while True:
            hits = page.get("hits", {}).get("hits", [])
            if not hits:
                break
            for hit in hits:
                fh.write(json.dumps(
                    {"_index": index, "_id": hit["_id"], "_source": hit["_source"]},
                    ensure_ascii=False,
                ) + "\n")
            count += len(hits)
            LOGGER.info("Dumped %d/%s documents", count, total)
            page = request_json(f"{es_url}/_search/scroll", method="POST",
                                payload={"scroll": scroll, "scroll_id": scroll_id})
            scroll_id = page.get("_scroll_id", scroll_id)

    # Best-effort scroll cleanup — the context expires on its own anyway.
    try:
        request_json(f"{es_url}/_search/scroll", method="DELETE",
                     payload={"scroll_id": scroll_id})
    except Exception:  # noqa: BLE001
        pass
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--es-url", default="http://localhost:9200", help="Elasticsearch base URL")
    parser.add_argument("--index", required=True, help="Index name to dump")
    parser.add_argument("--out", default=None, help="NDJSON output path (default: <index>_dump.json)")
    parser.add_argument("--schema-out", default=None, help="Schema output path (default: <index>_schema.json)")
    parser.add_argument("--batch-size", type=int, default=1000)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    es_url = args.es_url.rstrip("/")
    out = Path(args.out or f"{args.index}_dump.json")
    schema_out = Path(args.schema_out or f"{args.index}_schema.json")

    dump_schema(es_url, args.index, schema_out)
    count = dump_documents(es_url, args.index, out, args.batch_size)
    LOGGER.info("Done: %d documents → %s (schema → %s)", count, out, schema_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
