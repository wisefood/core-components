#!/usr/bin/env python3
"""Recreate the recipes index in Elasticsearch and import documents."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Sequence


LOGGER = logging.getLogger("elastic-init")
SCRIPT_DIR = Path(__file__).resolve().parent


def parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise argparse.ArgumentTypeError(f"Invalid boolean value: {value!r}")


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return parse_bool(value)


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    return int(value)


def build_log_file(log_dir: str, index_name: str, explicit_log_file: str | None) -> Path:
    if explicit_log_file:
        log_file = Path(explicit_log_file).expanduser().resolve()
        log_file.parent.mkdir(parents=True, exist_ok=True)
        return log_file

    directory = Path(log_dir).expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return directory / f"reindex_{index_name}_{timestamp}.log"


def configure_logging(log_file: Path) -> None:
    formatter = logging.Formatter(
        fmt="%(asctime)sZ | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    formatter.converter = time.gmtime

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(logging.INFO)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reset the recipes index, apply the schema, and import the dump."
    )
    parser.add_argument(
        "--input",
        default=os.getenv("IMPORT_FILE", str(SCRIPT_DIR / "recipes_dump.json")),
        help="Path to the JSON dump file.",
    )
    parser.add_argument(
        "--schema",
        default=os.getenv("SCHEMA_FILE", str(SCRIPT_DIR / "recipes_schema.json")),
        help="Path to the Elasticsearch schema JSON file.",
    )
    parser.add_argument(
        "--es-url",
        default=os.getenv("ES_URL", "http://localhost:9200"),
        help="Elasticsearch base URL.",
    )
    parser.add_argument(
        "--index",
        default=os.getenv("INDEX_NAME", "recipes"),
        help="Target index name.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=env_int("BATCH_SIZE", 1000),
        help="Documents per bulk request. Default: 1000.",
    )
    parser.add_argument(
        "--request-timeout",
        type=int,
        default=env_int("REQUEST_TIMEOUT", 120),
        help="HTTP timeout in seconds. Default: 120.",
    )
    parser.add_argument(
        "--log-every",
        type=int,
        default=env_int("LOG_EVERY", 5000),
        help="Emit progress every N imported docs. Default: 5000.",
    )
    parser.add_argument(
        "--max-docs",
        type=int,
        default=int(os.getenv("MAX_DOCS")) if os.getenv("MAX_DOCS") else None,
        help="Optional cap for test runs.",
    )
    parser.add_argument(
        "--log-dir",
        default=os.getenv("LOG_DIR", str(SCRIPT_DIR / "logs")),
        help="Directory for generated log files.",
    )
    parser.add_argument(
        "--log-file",
        default=os.getenv("LOG_FILE"),
        help="Explicit log file path. Overrides --log-dir when set.",
    )
    parser.add_argument(
        "--delete-index",
        dest="delete_index",
        action="store_true",
        help="Delete the index before recreating it.",
    )
    parser.add_argument(
        "--keep-index",
        dest="delete_index",
        action="store_false",
        help="Skip deleting the index first.",
    )
    parser.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="Validate files and count documents without calling Elasticsearch.",
    )
    parser.add_argument(
        "--no-dry-run",
        dest="dry_run",
        action="store_false",
        help="Run the full Elasticsearch workflow.",
    )
    parser.set_defaults(
        delete_index=env_bool("DELETE_INDEX", True),
        dry_run=env_bool("DRY_RUN", False),
    )
    return parser.parse_args()


def build_url(es_url: str, path: str = "") -> str:
    return urllib.parse.urljoin(es_url.rstrip("/") + "/", path.lstrip("/"))


def iter_json_array(path: Path, chunk_size: int = 1024 * 1024) -> Iterator[Any]:
    decoder = json.JSONDecoder()

    with path.open("r", encoding="utf-8") as handle:
        buffer = ""
        started = False
        finished = False

        while not finished:
            chunk = handle.read(chunk_size)
            eof = chunk == ""
            if chunk:
                buffer += chunk

            index = 0

            if not started:
                while index < len(buffer) and buffer[index].isspace():
                    index += 1
                if index == len(buffer):
                    if eof:
                        raise ValueError(f"{path} does not contain a JSON array.")
                    buffer = ""
                    continue
                if buffer[index] != "[":
                    raise ValueError(f"{path} must start with a JSON array.")
                started = True
                index += 1

            while True:
                while index < len(buffer) and buffer[index].isspace():
                    index += 1

                if index >= len(buffer):
                    break

                if buffer[index] == "]":
                    finished = True
                    index += 1
                    break

                try:
                    item, next_index = decoder.raw_decode(buffer, index)
                except json.JSONDecodeError:
                    if eof:
                        snippet = buffer[index : index + 120]
                        raise ValueError(
                            f"Could not decode JSON near: {snippet!r}"
                        ) from None
                    break

                yield item
                index = next_index

                while index < len(buffer) and buffer[index].isspace():
                    index += 1

                if index < len(buffer) and buffer[index] == ",":
                    index += 1
                    continue

                if index < len(buffer) and buffer[index] == "]":
                    finished = True
                    index += 1
                    break

                if index >= len(buffer):
                    break

                if eof:
                    raise ValueError("Malformed JSON array: expected ',' or ']'.")
                break

            buffer = buffer[index:]

            if eof and not finished:
                if buffer.strip():
                    raise ValueError("Unexpected trailing JSON content.")
                raise ValueError("JSON array ended before closing ']'.")


def normalize_doc(raw_doc: Any) -> Dict[str, Any]:
    if not isinstance(raw_doc, dict):
        raise ValueError(f"Each document must be an object, got {type(raw_doc).__name__}.")

    if "id" not in raw_doc:
        raise ValueError("Document is missing required field 'id'.")

    document = dict(raw_doc)
    document["id"] = str(document["id"])

    if "title" in document and document["title"] is not None:
        document["title"] = str(document["title"])

    return document


def chunked(documents: Iterable[Dict[str, Any]], batch_size: int) -> Iterator[List[Dict[str, Any]]]:
    batch: List[Dict[str, Any]] = []

    for document in documents:
        batch.append(document)
        if len(batch) >= batch_size:
            yield batch
            batch = []

    if batch:
        yield batch


def request_json(
    method: str,
    url: str,
    timeout: int,
    expected_statuses: Sequence[int],
    payload: Any | None = None,
    content_type: str = "application/json",
    log_body: bool = True,
    body_log_limit: int | None = 2000,
) -> Any:
    body = None
    headers: Dict[str, str] = {}

    if payload is not None:
        if isinstance(payload, bytes):
            body = payload
        else:
            body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = content_type

    request = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.getcode()
            raw_body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw_body = exc.read().decode("utf-8", errors="replace")
        if status not in expected_statuses:
            raise RuntimeError(
                f"{method} {url} failed with HTTP {status}: {raw_body[:1000]}"
            ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach Elasticsearch at {url}: {exc}") from exc

    LOGGER.info("HTTP %s %s -> %s", method, url, status)
    if log_body and raw_body:
        if body_log_limit is not None and len(raw_body) > body_log_limit:
            LOGGER.info(
                "Response body: %s... [truncated, total_chars=%s]",
                raw_body[:body_log_limit],
                len(raw_body),
            )
        else:
            LOGGER.info("Response body: %s", raw_body)

    if status not in expected_statuses:
        raise RuntimeError(f"{method} {url} returned unexpected HTTP {status}")

    if not raw_body:
        return None

    try:
        return json.loads(raw_body)
    except json.JSONDecodeError:
        return raw_body


def load_schema(schema_path: Path) -> Dict[str, Any]:
    with schema_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def build_bulk_payload(index: str, documents: List[Dict[str, Any]]) -> bytes:
    lines: List[str] = []

    for document in documents:
        action = {"index": {"_index": index, "_id": document["id"]}}
        lines.append(json.dumps(action, separators=(",", ":"), ensure_ascii=False))
        lines.append(json.dumps(document, separators=(",", ":"), ensure_ascii=False))

    return ("\n".join(lines) + "\n").encode("utf-8")


def post_bulk(es_url: str, payload: bytes, timeout: int) -> Dict[str, Any]:
    response = request_json(
        method="POST",
        url=build_url(es_url, "_bulk"),
        timeout=timeout,
        expected_statuses=(200,),
        payload=payload,
        content_type="application/x-ndjson",
        log_body=False,
    )

    if not isinstance(response, dict):
        raise RuntimeError(f"Unexpected bulk response: {response!r}")

    if response.get("errors"):
        failures = []
        for item in response.get("items", []):
            result = item.get("index", {})
            error = result.get("error")
            if error:
                failures.append(
                    {
                        "id": result.get("_id"),
                        "status": result.get("status"),
                        "type": error.get("type"),
                        "reason": error.get("reason"),
                    }
                )
                if len(failures) >= 5:
                    break
        raise RuntimeError(f"Bulk import reported item failures: {failures}")

    return response


def import_documents(args: argparse.Namespace, input_path: Path) -> int:
    imported = 0
    batches = 0
    next_log_threshold = args.log_every
    started_at = time.time()

    def documents() -> Iterator[Dict[str, Any]]:
        count = 0
        for raw_document in iter_json_array(input_path):
            yield normalize_doc(raw_document)
            count += 1
            if args.max_docs is not None and count >= args.max_docs:
                break

    for batch in chunked(documents(), args.batch_size):
        batches += 1
        if args.dry_run:
            imported += len(batch)
        else:
            response = post_bulk(
                es_url=args.es_url,
                payload=build_bulk_payload(args.index, batch),
                timeout=args.request_timeout,
            )
            imported += len(batch)
            LOGGER.info(
                "Imported batch %s with %s docs (es_took_ms=%s)",
                batches,
                len(batch),
                response.get("took"),
            )

        if imported >= next_log_threshold or (
            args.max_docs is not None and imported >= args.max_docs
        ):
            LOGGER.info("Processed %s documents so far", imported)
            while imported >= next_log_threshold:
                next_log_threshold += args.log_every

    elapsed = time.time() - started_at
    LOGGER.info("Import stage complete. Processed %s documents in %.2fs", imported, elapsed)
    return imported


def run(args: argparse.Namespace) -> int:
    if args.batch_size <= 0:
        raise ValueError("--batch-size must be greater than zero.")
    if args.log_every <= 0:
        raise ValueError("--log-every must be greater than zero.")

    input_path = Path(args.input).expanduser().resolve()
    schema_path = Path(args.schema).expanduser().resolve()

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    if not schema_path.exists():
        raise FileNotFoundError(f"Schema file not found: {schema_path}")

    log_file = build_log_file(args.log_dir, args.index, args.log_file)
    configure_logging(log_file)

    LOGGER.info("Starting recipes Elasticsearch sync")
    LOGGER.info("Log file: %s", log_file)
    LOGGER.info(
        "Settings: es_url=%s index=%s input=%s schema=%s delete_index=%s dry_run=%s batch_size=%s",
        args.es_url,
        args.index,
        input_path,
        schema_path,
        args.delete_index,
        args.dry_run,
        args.batch_size,
    )

    schema = load_schema(schema_path)

    if args.dry_run:
        LOGGER.info("Dry run enabled. Elasticsearch calls will be skipped.")
        import_documents(args, input_path)
        LOGGER.info("Dry run complete")
        return 0

    index_path = urllib.parse.quote(args.index, safe="")

    request_json(
        method="GET",
        url=build_url(args.es_url),
        timeout=args.request_timeout,
        expected_statuses=(200,),
    )

    if args.delete_index:
        request_json(
            method="DELETE",
            url=build_url(args.es_url, index_path),
            timeout=args.request_timeout,
            expected_statuses=(200, 404),
        )
    else:
        LOGGER.info("Skipping index deletion because delete_index=%s", args.delete_index)

    request_json(
        method="PUT",
        url=build_url(args.es_url, index_path),
        timeout=args.request_timeout,
        expected_statuses=(200, 201),
        payload=schema,
    )

    imported = import_documents(args, input_path)

    request_json(
        method="POST",
        url=build_url(args.es_url, f"{index_path}/_refresh"),
        timeout=args.request_timeout,
        expected_statuses=(200,),
    )

    count_response = request_json(
        method="GET",
        url=build_url(args.es_url, f"{index_path}/_count"),
        timeout=args.request_timeout,
        expected_statuses=(200,),
    )

    count = count_response.get("count") if isinstance(count_response, dict) else None
    LOGGER.info("Finished successfully. Imported=%s index_count=%s", imported, count)
    return 0


def main() -> int:
    return run(parse_args())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover - CLI safety net
        LOGGER.error("%s", exc)
        raise SystemExit(1) from exc
