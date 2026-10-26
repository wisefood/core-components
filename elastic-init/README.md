# elastic-init

Loads the RecipeWrangler Elasticsearch handoff bundle into a live cluster
**without disturbing any other index**.

## What is in the image

`bundle/` is the 2026-07-27 handoff from `RecipeWrangler-Backend`
(`integrate/elasticsearch-main`, commit `8856063`). It carries two indices:

| Index                   | Docs    | Store  | Alias                |
| ----------------------- | ------- | ------ | -------------------- |
| `recipes_v2`            | 811,540 | ~428MB | –                    |
| `ingredient_vectors_v1` | 117,917 | ~917MB | `ingredient_vectors` |

`recipes_v2` adds the title-search fields and the EU / Irish / Hungarian
Nutri-Scores. `ingredient_vectors_v1` is a 384-dim `dense_vector` HNSW index
used for ingredient and sustainability matching.

## Scope guarantee

`restore.py` derives its target list from `bundle/metadata/manifest.json` and
will only ever delete, create, or write those index names. It cannot be pointed
at an index the manifest does not declare — `INDICES` names outside the manifest
abort the run with exit code 2.

Every run logs the split up front and re-checks it at the end:

```
WILL MODIFY (2): ingredient_vectors_v1, recipes_v2
WILL DROP (1): recipes
WILL NOT TOUCH (14): articles, artifacts, fctables, foodscholar_cards, ...
...
Verified all 14 unrelated indices are still present
```

The one exception is `DROP_INDICES`: an explicit list of superseded indices to
delete. It defaults to `recipes` — the v1 index that `recipes_v2` replaces.

The drop is **interlocked**: it runs only after every restore has succeeded and
matched its manifest count. If `recipes_v2` fails to load, `recipes` is left in
place as a fallback and the run exits non-zero:

```
Skipping the drop of recipes because recipes_v2 did not restore cleanly;
the superseded data stays put as a fallback
```

Set `DROP_INDICES=""` to keep `recipes`. A name that is also a restore target
aborts the run with exit code 2.

## Running it

In-cluster (this is what `es-init-job` does — see
`platform-deployment/lib/sysinit.libsonnet`):

```bash
kubectl -n wf-prod delete job es-init-job --ignore-not-found
tk apply environments/wf-prod   # or re-create the job by hand
kubectl -n wf-prod logs -f job/es-init-job
```

Ad hoc, against a port-forwarded cluster:

```bash
kubectl -n wf-prod port-forward svc/elastic 9200:9200 &
ES_URL=http://localhost:9200 python3 restore.py
```

Only one of the two indices:

```bash
INDICES=recipes_v2 python3 restore.py
```

## Configuration

| Variable             | Default        | Purpose                                                          |
| -------------------- | -------------- | ---------------------------------------------------------------- |
| `ES_URL`             | localhost:9200 | Target cluster                                                    |
| `BUNDLE_DIR`         | `/app/bundle`  | Bundle root (must contain `metadata/manifest.json`)               |
| `INDICES`            | *(all)*        | Comma-separated subset of the manifest's indices                  |
| `DROP_INDICES`       | `recipes`      | Superseded indices to delete after every restore succeeds         |
| `RECREATE_INDEX`     | `true`         | Delete + recreate before loading (the overwrite path)             |
| `SKIP_IF_CURRENT`    | `false`        | No-op an index that already holds exactly the manifest doc count  |
| `VERIFY_COUNTS`      | `true`         | Fail the run if a restored count misses the manifest              |
| `NUMBER_OF_REPLICAS` | `0`            | Overrides the bundle's replica count; 0 suits a single-node ES    |
| `BATCH_SIZE`         | `1000`         | Max docs per `_bulk` request                                      |
| `BATCH_BYTES`        | `8388608`      | Flush a batch at this payload size — this is what bounds the      |
|                      |                | dense-vector batches, which hit the byte cap long before 1000 docs |
| `MAX_RETRIES`        | `6`            | Retries for connection errors, 429/5xx, and rejected bulk items    |

Set `RECREATE_INDEX=false` to upsert into an existing index instead of
replacing it — documents keep their `_id`, so this is an in-place update.

## Disk headroom

The `elastic-storage` PVC in `wf-prod` is 5Gi. `ingredient_vectors_v1` adds
~917MB plus transient merge space. Check before running:

```bash
kubectl -n wf-prod exec elastic-0 -- df -h /usr/share/elasticsearch/data
```

Restoring `recipes_v2` first frees its old ~428MB before the vectors land,
which is why the manifest order matters. If headroom is short, grow the PVC
(`lib/elastic.libsonnet`) rather than deleting unrelated indices.

## Rebuilding the image

```bash
make verify            # sha256 the bundle against metadata/checksums.sha256
make VERSION=2026.07.27 all
```

`make` tags both `wisefood/elastic-init:latest` and `:$(VERSION)`. Bump
`VERSION` whenever the bundle changes so a rollback is a tag change.

The `*.ndjson.gz` archives are gitignored — the bundle travels in the image,
not in git. Mappings, settings, and the manifest stay tracked so schema changes
are reviewable.

## Ad-hoc tools

`restore.py` + `bundle/` replaced the Jul-2026 hand-rolled dump/import cycle.
Two general-purpose scripts survive it and ship in the image:

- `dump.py` — scroll one live index out to gzip-able NDJSON. This is how you
  regenerate a bundle archive.
- `import.py` — load one index from a JSON/NDJSON dump plus a
  `{settings, mappings}` schema file.

`import.py` now **requires** `--input`, `--schema` and `--index` (or the
`IMPORT_FILE` / `SCHEMA_FILE` / `INDEX_NAME` env vars). It used to default to
`recipes_dump.json`, `recipes_schema.json` and the index name `recipes`; those
files are gone and that index is retired, so a bare `python3 import.py` would
have been either a no-op or a surprise.

### What was removed, 2026-07-28

`bundle/` supersedes the whole previous generation, so it went:

| Path                                              | Size  | Why                                                    |
| ------------------------------------------------- | ----- | ------------------------------------------------------ |
| `recipes_v2_dump.json`                             | 713MB | Superseded by `bundle/.../recipes_v2_documents.ndjson.gz` |
| `recipes_dump.json`                                | 60KB  | Sample data for the retired v1 `recipes` index          |
| `recipes_v2_schema.json`                           | 2.4KB | Strict subset of the bundle mapping (no `title_normalized`) |
| `recipes_schema.json`                              | 2.4KB | Older generation still: `text`+`.keyword` where the bundle has `keyword`, `long` where it has `float`, and none of the `nutri_*` fields |
| `_state/`, `snapshot_cache/`, `nodes`, `node.lock` | 100KB | Stray Lucene state from an Elasticsearch that once ran in this directory |
| `logs/`, `__pycache__/`                            | 120KB | Regenerated on demand                                   |

`bundle/elasticsearch/*_mapping.json` is now the single authoritative schema.
