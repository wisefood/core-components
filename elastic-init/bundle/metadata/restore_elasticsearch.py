#!/usr/bin/env python3
"""Restore a gzip-compressed RecipeWrangler Elasticsearch NDJSON export."""

from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path

import requests


def load_mappings(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if len(payload) != 1:
        raise ValueError(f"Expected one index in {path}")
    return next(iter(payload.values()))["mappings"]


def flush_batch(es_url: str, index: str, records: list[dict]) -> tuple[int, int]:
    lines: list[str] = []
    for record in records:
        lines.append(json.dumps({"index": {"_index": index, "_id": record["_id"]}}))
        lines.append(json.dumps(record["_source"], ensure_ascii=False))
    response = requests.post(
        f"{es_url}/_bulk",
        headers={"Content-Type": "application/x-ndjson"},
        data=("\n".join(lines) + "\n").encode("utf-8"),
        timeout=180,
    )
    response.raise_for_status()
    result = response.json()
    succeeded = sum(1 for item in result["items"] if 200 <= item["index"]["status"] < 300)
    return succeeded, len(records) - succeeded


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mapping", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--index", required=True)
    parser.add_argument("--alias")
    parser.add_argument("--es-url", default="http://localhost:9200")
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--recreate-index", action="store_true")
    args = parser.parse_args()

    es_url = args.es_url.rstrip("/")
    index_url = f"{es_url}/{args.index}"
    if args.recreate_index:
        response = requests.delete(index_url, timeout=60)
        if response.status_code not in {200, 404}:
            response.raise_for_status()
        response = requests.put(
            index_url,
            json={"mappings": load_mappings(args.mapping)},
            timeout=60,
        )
        response.raise_for_status()

    total_ok = 0
    total_failed = 0
    batch: list[dict] = []
    opener = gzip.open if args.input.suffix == ".gz" else open
    with opener(args.input, "rt", encoding="utf-8") as handle:
        for line in handle:
            batch.append(json.loads(line))
            if len(batch) >= args.batch_size:
                ok, failed = flush_batch(es_url, args.index, batch)
                total_ok += ok
                total_failed += failed
                batch.clear()
                print(f"indexed={total_ok} failed={total_failed}", flush=True)
        if batch:
            ok, failed = flush_batch(es_url, args.index, batch)
            total_ok += ok
            total_failed += failed

    requests.post(f"{index_url}/_refresh", timeout=60).raise_for_status()
    if args.alias:
        requests.post(
            f"{es_url}/_aliases",
            json={"actions": [{"add": {"index": args.index, "alias": args.alias}}]},
            timeout=60,
        ).raise_for_status()
    print(f"complete indexed={total_ok} failed={total_failed}")
    if total_failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
