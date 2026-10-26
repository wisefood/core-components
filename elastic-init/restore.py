#!/usr/bin/env python3
"""Restore a RecipeWrangler Elasticsearch handoff bundle into a live cluster.

Scope guarantee: this script only ever writes to the indices named in the
bundle manifest (optionally narrowed further by INDICES), plus any superseded
index explicitly listed in DROP_INDICES. Every other index in the target
cluster is left completely alone -- it is never read for mutation, never
deleted, and never reindexed. The pre-flight logs an explicit
touched/untouched inventory so the job log is an audit trail.

Standard library only, so the image needs no pip install (see import.py).
"""

from __future__ import annotations

import argparse
import gzip
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple


LOGGER = logging.getLogger("elastic-init")
SCRIPT_DIR = Path(__file__).resolve().parent

# Index settings Elasticsearch reports back but refuses on create.
NON_CREATABLE_SETTINGS = {
    "uuid",
    "provided_name",
    "creation_date",
    "creation_date_string",
    "version",
    "resize",
    "history",
    "verified_before_close",
    "frozen",
}

RETRYABLE_STATUS = {429, 502, 503, 504}


def parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise argparse.ArgumentTypeError(f"Invalid boolean value: {value!r}")


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    return default if value is None else parse_bool(value)


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    return default if value is None else int(value)


def configure_logging(log_dir: str) -> None:
    formatter = logging.Formatter(fmt="%(asctime)sZ | %(levelname)s | %(message)s")
    formatter.converter = time.gmtime

    LOGGER.setLevel(logging.INFO)
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    LOGGER.addHandler(stream)

    if not log_dir:
        return
    try:
        directory = Path(log_dir).expanduser()
        directory.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        handler = logging.FileHandler(directory / f"restore_{stamp}.log", encoding="utf-8")
        handler.setFormatter(formatter)
        LOGGER.addHandler(handler)
    except OSError as exc:  # read-only rootfs should not fail the job
        LOGGER.warning("File logging disabled (%s)", exc)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--es-url", default=os.getenv("ES_URL", "http://localhost:9200"))
    parser.add_argument(
        "--bundle-dir",
        type=Path,
        default=Path(os.getenv("BUNDLE_DIR", str(SCRIPT_DIR / "bundle"))),
    )
    parser.add_argument(
        "--indices",
        default=os.getenv("INDICES", ""),
        help="Comma-separated subset of manifest indices to restore (default: all).",
    )
    parser.add_argument(
        "--drop-indices",
        default=os.getenv("DROP_INDICES", ""),
        help="Comma-separated superseded indices to delete once every restore "
        "has succeeded. Names must not overlap the restore targets.",
    )
    parser.add_argument("--recreate-index", type=parse_bool, default=env_bool("RECREATE_INDEX", True))
    parser.add_argument(
        "--skip-if-current",
        type=parse_bool,
        default=env_bool("SKIP_IF_CURRENT", False),
        help="Skip an index that already holds exactly the manifest doc count.",
    )
    parser.add_argument("--batch-size", type=int, default=env_int("BATCH_SIZE", 1000))
    parser.add_argument(
        "--batch-bytes",
        type=int,
        default=env_int("BATCH_BYTES", 8 * 1024 * 1024),
        help="Flush a bulk request once its payload reaches this size (keeps "
        "dense-vector batches from blowing past http.max_content_length).",
    )
    parser.add_argument("--request-timeout", type=int, default=env_int("REQUEST_TIMEOUT", 300))
    parser.add_argument("--max-retries", type=int, default=env_int("MAX_RETRIES", 6))
    parser.add_argument("--log-every", type=int, default=env_int("LOG_EVERY", 25000))
    parser.add_argument("--log-dir", default=os.getenv("LOG_DIR", str(SCRIPT_DIR / "logs")))
    parser.add_argument(
        "--number-of-replicas",
        default=os.getenv("NUMBER_OF_REPLICAS"),
        help="Override the bundle's replica count (single-node clusters want 0).",
    )
    parser.add_argument(
        "--verify-counts",
        type=parse_bool,
        default=env_bool("VERIFY_COUNTS", True),
        help="Fail the run if a restored index does not match the manifest count.",
    )
    return parser.parse_args()


def request_json(
    method: str,
    url: str,
    timeout: int,
    payload: bytes | None = None,
    content_type: str = "application/json",
    ok_status: Tuple[int, ...] = (),
) -> Tuple[int, Any]:
    """Issue a request; return (status, decoded body). Raises on unexpected status."""
    request = urllib.request.Request(url, data=payload, method=method)
    if payload is not None:
        request.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
            return response.status, (json.loads(body) if body else None)
    except urllib.error.HTTPError as exc:
        body = exc.read()
        if exc.code in ok_status:
            return exc.code, (json.loads(body) if body else None)
        detail = body.decode("utf-8", "replace")[:2000]
        raise RuntimeError(f"{method} {url} -> HTTP {exc.code}: {detail}") from exc


def request_with_retry(
    method: str,
    url: str,
    timeout: int,
    max_retries: int,
    payload: bytes | None = None,
    content_type: str = "application/json",
    ok_status: Tuple[int, ...] = (),
) -> Tuple[int, Any]:
    delay = 2.0
    for attempt in range(1, max_retries + 1):
        try:
            return request_json(method, url, timeout, payload, content_type, ok_status)
        except urllib.error.URLError as exc:
            reason = f"connection error: {exc.reason}"
        except (TimeoutError, ConnectionError) as exc:
            reason = f"transport error: {exc}"
        except RuntimeError as exc:
            reason = str(exc)
            if not any(f"HTTP {code}" in reason for code in RETRYABLE_STATUS):
                raise
        if attempt == max_retries:
            raise RuntimeError(f"{method} {url} failed after {max_retries} attempts: {reason}")
        LOGGER.warning("%s %s attempt %d/%d failed (%s); retrying in %.0fs",
                       method, url, attempt, max_retries, reason, delay)
        time.sleep(delay)
        delay = min(delay * 2, 60.0)
    raise AssertionError("unreachable")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def single_index_body(path: Path, key: str) -> Dict[str, Any]:
    """Unwrap ES's {"<index>": {"mappings"|"settings": ...}} response format."""
    payload = load_json(path)
    if len(payload) != 1:
        raise ValueError(f"Expected exactly one index in {path}, found {list(payload)}")
    return next(iter(payload.values())).get(key, {})


def sanitize_settings(settings: Dict[str, Any], replicas_override: str | None) -> Dict[str, Any]:
    index_settings = dict(settings.get("index", {}))
    for key in NON_CREATABLE_SETTINGS:
        index_settings.pop(key, None)
    if replicas_override is not None:
        index_settings["number_of_replicas"] = str(replicas_override)
    return {"index": index_settings} if index_settings else {}


def iter_bulk_batches(
    path: Path, index: str, batch_size: int, batch_bytes: int
) -> Iterator[Tuple[List[bytes], int]]:
    """Stream the gzip NDJSON export as (bulk action lines, document count)."""
    lines: List[bytes] = []
    docs = 0
    size = 0
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as handle:
        for raw in handle:
            raw = raw.strip()
            if not raw:
                continue
            record = json.loads(raw)
            action = {"index": {"_index": index}}
            if record.get("_id") is not None:
                action["index"]["_id"] = record["_id"]
            action_line = json.dumps(action).encode("utf-8")
            source_line = json.dumps(record["_source"], ensure_ascii=False).encode("utf-8")
            lines.append(action_line)
            lines.append(source_line)
            docs += 1
            size += len(action_line) + len(source_line) + 2
            if docs >= batch_size or size >= batch_bytes:
                yield lines, docs
                lines, docs, size = [], 0, 0
    if docs:
        yield lines, docs


def post_bulk(es_url: str, lines: List[bytes], args: argparse.Namespace) -> Tuple[int, List[str]]:
    """Bulk-index one batch, retrying only the items ES rejected as overloaded.

    Returns (documents indexed, up to 20 sample error messages). The caller
    derives the failure count from the batch size, so the samples are for
    diagnosis only and are deliberately capped.
    """
    pending = lines
    errors: List[str] = []
    succeeded = 0
    delay = 2.0

    for attempt in range(1, args.max_retries + 1):
        payload = b"\n".join(pending) + b"\n"
        _, result = request_with_retry(
            "POST",
            f"{es_url}/_bulk",
            args.request_timeout,
            args.max_retries,
            payload,
            content_type="application/x-ndjson",
        )
        retry_lines: List[bytes] = []
        for position, item in enumerate(result.get("items", [])):
            outcome = next(iter(item.values()))
            status = outcome.get("status", 500)
            if 200 <= status < 300:
                succeeded += 1
                continue
            error_type = (outcome.get("error") or {}).get("type", "unknown")
            if status in RETRYABLE_STATUS or error_type == "es_rejected_execution_exception":
                retry_lines.append(pending[position * 2])
                retry_lines.append(pending[position * 2 + 1])
                continue
            if len(errors) < 20:
                errors.append(f"_id={outcome.get('_id')} status={status} {error_type}: "
                              f"{(outcome.get('error') or {}).get('reason', '')[:300]}")

        if not retry_lines:
            return succeeded, errors
        if attempt == args.max_retries:
            LOGGER.error("%d docs still rejected after %d attempts; giving up on this batch",
                         len(retry_lines) // 2, args.max_retries)
            return succeeded, errors
        LOGGER.warning("%d docs rejected (backpressure); retrying in %.0fs",
                       len(retry_lines) // 2, delay)
        time.sleep(delay)
        delay = min(delay * 2, 60.0)
        pending = retry_lines

    return succeeded, errors


def index_exists(es_url: str, index: str, args: argparse.Namespace) -> bool:
    status, _ = request_with_retry(
        "HEAD", f"{es_url}/{index}", args.request_timeout, args.max_retries, ok_status=(404,)
    )
    return status == 200


def count_docs(es_url: str, index: str, args: argparse.Namespace) -> int:
    status, body = request_with_retry(
        "GET", f"{es_url}/{index}/_count", args.request_timeout, args.max_retries, ok_status=(404,)
    )
    return 0 if status == 404 else int(body["count"])


def list_indices(es_url: str, args: argparse.Namespace) -> List[str]:
    _, body = request_with_retry(
        "GET", f"{es_url}/_cat/indices?format=json&h=index", args.request_timeout, args.max_retries
    )
    return sorted(entry["index"] for entry in body or [])


def point_alias(es_url: str, alias: str, index: str, args: argparse.Namespace) -> None:
    """Atomically move `alias` onto `index`, detaching it from anything else."""
    status, body = request_with_retry(
        "GET", f"{es_url}/_alias/{alias}", args.request_timeout, args.max_retries, ok_status=(404,)
    )
    actions: List[Dict[str, Any]] = []
    if status == 200:
        for current in body or {}:
            if current != index:
                actions.append({"remove": {"index": current, "alias": alias}})
    actions.append({"add": {"index": index, "alias": alias}})
    request_with_retry(
        "POST",
        f"{es_url}/_aliases",
        args.request_timeout,
        args.max_retries,
        json.dumps({"actions": actions}).encode("utf-8"),
    )
    LOGGER.info("Alias %r now points at %r", alias, index)


def drop_superseded(
    es_url: str, names: List[str], args: argparse.Namespace
) -> List[str]:
    """Delete indices the new bundle replaces. Only called once every restore
    succeeded, so a failed load never removes the fallback it supersedes."""
    failures: List[str] = []
    for name in names:
        try:
            if not index_exists(es_url, name, args):
                LOGGER.info("[%s] superseded index already absent; nothing to drop", name)
                continue
            count = count_docs(es_url, name, args)
            LOGGER.warning("[%s] dropping superseded index (%d docs)", name, count)
            request_with_retry(
                "DELETE", f"{es_url}/{name}", args.request_timeout, args.max_retries,
                ok_status=(404,),
            )
            LOGGER.info("[%s] dropped", name)
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("[%s] drop failed: %s", name, exc)
            failures.append(name)
    return failures


def restore_index(
    es_url: str, name: str, spec: Dict[str, Any], bundle: Path, args: argparse.Namespace
) -> bool:
    expected = int(spec.get("documents", 0))
    archive = bundle / spec["archive"]
    mapping_path = bundle / spec["mapping"]
    settings_path = bundle / spec["settings"] if spec.get("settings") else None
    alias = spec.get("alias")

    for required in (archive, mapping_path):
        if not required.exists():
            raise FileNotFoundError(f"Bundle file missing: {required}")

    if args.skip_if_current and index_exists(es_url, name, args):
        current = count_docs(es_url, name, args)
        if current == expected:
            LOGGER.info("[%s] already holds %d docs; skipping (SKIP_IF_CURRENT)", name, current)
            if alias:
                point_alias(es_url, alias, name, args)
            return True

    body: Dict[str, Any] = {"mappings": single_index_body(mapping_path, "mappings")}
    if settings_path and settings_path.exists():
        settings = sanitize_settings(
            single_index_body(settings_path, "settings"), args.number_of_replicas
        )
        if settings:
            body["settings"] = settings

    if args.recreate_index:
        LOGGER.info("[%s] deleting existing index (this index only)", name)
        request_with_retry(
            "DELETE", f"{es_url}/{name}", args.request_timeout, args.max_retries, ok_status=(404,)
        )
        LOGGER.info("[%s] creating index with bundle mappings/settings", name)
        request_with_retry(
            "PUT",
            f"{es_url}/{name}",
            args.request_timeout,
            args.max_retries,
            json.dumps(body).encode("utf-8"),
        )
    elif not index_exists(es_url, name, args):
        LOGGER.info("[%s] index absent; creating it", name)
        request_with_retry(
            "PUT",
            f"{es_url}/{name}",
            args.request_timeout,
            args.max_retries,
            json.dumps(body).encode("utf-8"),
        )

    LOGGER.info("[%s] importing %s (expecting %d docs)", name, archive.name, expected)
    started = time.monotonic()
    indexed = 0
    failed = 0
    reported = 0
    samples: List[str] = []

    for lines, docs in iter_bulk_batches(archive, name, args.batch_size, args.batch_bytes):
        ok, errors = post_bulk(es_url, lines, args)
        indexed += ok
        failed += docs - ok
        for message in errors:
            if message and len(samples) < 20:
                samples.append(message)
        if args.log_every and indexed - reported >= args.log_every:
            reported = indexed
            elapsed = time.monotonic() - started
            rate = indexed / elapsed if elapsed else 0.0
            LOGGER.info("[%s] indexed=%d failed=%d (%.0f docs/s)", name, indexed, failed, rate)

    request_with_retry("POST", f"{es_url}/{name}/_refresh", args.request_timeout, args.max_retries)
    final = count_docs(es_url, name, args)
    elapsed = time.monotonic() - started
    LOGGER.info("[%s] done in %.1fs: indexed=%d failed=%d count=%d expected=%d",
                name, elapsed, indexed, failed, final, expected)

    for message in samples:
        LOGGER.error("[%s] %s", name, message)

    # The alias is only moved once the load verifies, so readers are never
    # pointed at a half-populated index.
    if failed:
        LOGGER.error("[%s] %d documents failed to index", name, failed)
        return False
    if args.verify_counts and final != expected:
        LOGGER.error("[%s] count mismatch: cluster=%d manifest=%d", name, final, expected)
        return False

    if alias:
        point_alias(es_url, alias, name, args)
    return True


def run(args: argparse.Namespace) -> int:
    es_url = args.es_url.rstrip("/")
    bundle = args.bundle_dir.expanduser().resolve()
    manifest_path = bundle / "metadata" / "manifest.json"
    if not manifest_path.exists():
        LOGGER.error("No manifest at %s -- is BUNDLE_DIR correct?", manifest_path)
        return 2

    manifest = load_json(manifest_path)
    available = manifest.get("components", {}).get("elasticsearch", {}).get("indices", {})
    if not available:
        LOGGER.error("Manifest %s declares no Elasticsearch indices", manifest_path)
        return 2

    requested = [name.strip() for name in args.indices.split(",") if name.strip()]
    unknown = [name for name in requested if name not in available]
    if unknown:
        LOGGER.error("INDICES names not present in the bundle manifest: %s", ", ".join(unknown))
        return 2
    targets = {name: available[name] for name in (requested or available)}

    drops = [name.strip() for name in args.drop_indices.split(",") if name.strip()]
    overlap = [name for name in drops if name in targets]
    if overlap:
        LOGGER.error("DROP_INDICES overlaps the restore targets: %s", ", ".join(overlap))
        return 2

    _, info = request_with_retry("GET", es_url, args.request_timeout, args.max_retries)
    LOGGER.info("Connected to %s (Elasticsearch %s)", es_url, info["version"]["number"])
    LOGGER.info("Bundle %s exported %s from %s",
                bundle, manifest.get("export_date", "?"), manifest.get("project", "?"))

    existing = list_indices(es_url, args)
    in_scope = set(targets) | set(drops)
    untouched = [name for name in existing if name not in in_scope]
    LOGGER.info("WILL MODIFY (%d): %s", len(targets), ", ".join(sorted(targets)))
    if drops:
        LOGGER.warning("WILL DROP (%d): %s", len(drops), ", ".join(drops))
    LOGGER.info("WILL NOT TOUCH (%d): %s", len(untouched), ", ".join(untouched) or "<none>")

    failures: List[str] = []
    for name, spec in targets.items():
        try:
            if not restore_index(es_url, name, spec, bundle, args):
                failures.append(name)
        except Exception as exc:  # noqa: BLE001 - one bad index must not hide the rest
            LOGGER.exception("[%s] restore failed: %s", name, exc)
            failures.append(name)

    if drops:
        if failures:
            LOGGER.error("Skipping the drop of %s because %s did not restore cleanly; "
                         "the superseded data stays put as a fallback",
                         ", ".join(drops), ", ".join(sorted(set(failures))))
        else:
            failures.extend(drop_superseded(es_url, drops, args))

    after = list_indices(es_url, args)
    lost = [name for name in untouched if name not in after]
    if lost:
        LOGGER.error("Unrelated indices disappeared during the run: %s", ", ".join(lost))
        failures.extend(lost)
    else:
        LOGGER.info("Verified all %d unrelated indices are still present", len(untouched))

    if failures:
        LOGGER.error("Restore FAILED for: %s", ", ".join(sorted(set(failures))))
        return 1
    LOGGER.info("Restore complete for: %s", ", ".join(sorted(targets)))
    return 0


def main() -> int:
    args = parse_args()
    configure_logging(args.log_dir)
    try:
        return run(args)
    except KeyboardInterrupt:
        LOGGER.error("Interrupted")
        return 130
    except Exception as exc:  # noqa: BLE001
        LOGGER.exception("Fatal: %s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
