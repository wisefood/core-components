# RecipeWrangler data handoff — 2026-08-25

The data state for the v4 regional API (RecipeWrangler-Backend `main` at the
merge of PR #10). Sourced from `dumps/20260825173000-full/2026-08-25`; every
file here matched `SHA256SUMS` in that bundle when it was assembled.

## Included

- `elasticsearch/recipes_v4_no_heuristic_cost_20260825_*`: mappings, settings
  and all 7,628 recipe documents, alias `recipes`. Carries the v4 facet set —
  `convenience`, `nutrition_claims`, `seasonality` — and the regional
  Nutri-Score quartets for `eu`, `ie`, `hu` and `slovenian`.
- `elasticsearch/ingredient_vectors_v1_*`: mappings, settings and all 138,930
  vector documents, alias `ingredient_vectors`. Includes the new
  `nutritional_ingredients_slovenian` (320) and `foodon_classes` (39,278)
  collections; `usda_ingredients` (7,793) is retained because USDA still backs
  portion weights even though it is no longer a nutrition source.

## Not included

Postgres and Neo4j are shipped as their own images, not through this bundle:

- `nutrients` Postgres → `core-components/postgres-rw` (bakes `nutrients.dump`,
  restored by `docker-entrypoint-initdb.d` on an **empty** data directory only).
- Neo4j graph → `RecipeWrangler-Backend/neo4j-docker` (bakes
  `/import/neo4j.dump`; the StatefulSet's `neo4j-import` initContainer loads it
  only when `/data/databases/neo4j` is absent).

Their row/node counts are recorded under `components` in `manifest.json` so this
bundle still identifies the data generation it belongs to.

## Restoring

`restore.py` (the image entrypoint) reads `manifest.json` and, per index,
recreates it from the bundled mappings/settings, bulk-loads the archive, and
verifies the document count. Because the recipe index has its own physical
name, the restore **adds** an index and then atomically moves the `recipes`
alias onto it — the previously live `recipes_v4` is untouched and remains the
rollback. Drop it by hand once you are satisfied.

Do not put `recipes` in `DROP_INDICES`: it names the alias, not an index, and ES
refuses a delete-by-alias, so it can only produce a spurious failure.

## Compatibility

The recipe mapping is `dynamic: strict`, and its field set is mutually
exclusive with the pre-v4 index — `nutri_*_us` and `nutri_*_si` are gone,
`nutri_*_slovenian`, `convenience`, `nutrition_claims` and `seasonality` are
new. Code from before the v4 merge will fail writes against this index with
`strict_dynamic_mapping_exception`, and vice versa. Deploy the two together.
