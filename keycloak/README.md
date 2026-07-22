# Keycloak IdP Image

Keycloak 25.0 plus the WiseFood Keycloakify theme in `theme/wisefood-theme.jar`,
baked in with `kc.sh build` (see `Dockerfile`). `make build push` publishes
`wisefood/keycloak:latest`.

## ⚠ The theme jar has local modifications — do not overwrite it blindly

`theme/wisefood-theme.jar` is a **build artifact whose source is not in this
workspace**. It was patched in place to add Slovene. If you rebuild the theme
from its original Keycloakify project and drop the new jar here, **Slovene
silently reverts to English** and the pilot regresses.

If you do rebuild, re-apply the patch afterwards and re-run the verification
below. The patch script is reproducible and idempotent-guarded; ask for
`build_sl_theme.py` (it refuses to overwrite non-empty message bundles).

### What was changed and why

Slovene was reported missing from the registration page and the confirmation
email. Upstream Keycloak only gained Slovene in Feb 2025
([PR #37012](https://github.com/keycloak/keycloak/pull/37012)) — *after* the
25.0 image we run was cut — so the base themes here ship **no `sl` at all**.
The bundles were imported verbatim from keycloak/keycloak
`themes/src/main/resources-community/theme/base/<type>/messages/messages_sl.properties`
(and `js/apps/account-ui/maven-resources-community/...` for the v3 account
console), which is Apache-2.0 licensed.

| Theme type | Change | Slovene coverage |
|---|---|---|
| `login` | added `messages_sl.properties`, added `sl` to `locales=` | 452 / 467 keys |
| `account` | replaced an **empty 0-byte `messages_sl` stub** | 61 / 234 keys (upstream gap) |
| `email` | **new theme type** (`parent=base`, `locales=en,sl`) + `messages_sl` | 65 keys |
| `META-INF/keycloak-themes.json` | declared the new `email` type | — |

Two traps worth knowing:

* The theme **bundles its own full copy of every base message key**, so it
  shadows `base` entirely. Adding `sl` to `base` would have had no effect —
  it has to go inside this jar.
* `account`/`admin` already listed `sl` in `locales=` while shipping *empty*
  `messages_sl.properties` files. That is why Slovene appeared selectable but
  rendered English.

Untranslated keys fall back to `messages_en.properties` by design, rather than
being machine-translated. The ~15 uncovered `login` keys are mostly CLI
device-flow strings (`browserContinue*`) and dynamic user-profile widgets
(`addValue`, `selectAnOption`); a native speaker should review them before the
pilot if those flows are reachable.

Message bundles in this theme are `\uXXXX`-escaped, **not** raw UTF-8 — match
that convention or diacritics break.

### Realm settings this depends on

Both live in `../keycloak-init/run.py` (`configure_realm_settings`):

* `supportedLocales` must contain `sl`, or Keycloak ignores the locale entirely.
* `emailTheme` must be set to `keycloakify-starter`, or emails resolve from
  `base` — which has no Slovene — even though the login page is translated.

The app also has to forward the user's language: `kc.login()`/`kc.register()`
pass `locale` from the `wisefood_locale` cookie (see
`wisefood-ui/app/services/keycloak.ts`). Without it the language chosen in the
app is dropped at the Keycloak boundary.

### Verifying Slovene after a change

```sh
make build
docker run -d --name kc-check -p 8099:8080 \
  -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -e KC_HTTP_ENABLED=true -e KC_HOSTNAME_STRICT=false \
  --entrypoint /opt/keycloak/bin/kc.sh wisefood/keycloak:latest start-dev
```

Note the `--entrypoint` override: the image's own entrypoint already appends
`start`, so passing `start-dev` without it fails with `Unknown option`.

Then confirm all three theme types register with `sl` (admin token → 
`/admin/serverinfo`, field `themes.<type>[].locales`). Expect:

```
login    sl present: True
email    sl present: True
account  sl present: True
```

For an end-to-end check, open the registration page, follow the `sl` entry in
the locale switcher, and confirm the form reads `Ime` / `Priimek` /
`E-poštni naslov` with no English left. The locale switch must reuse the same
auth session — fetching the switch URL with a fresh cookie jar returns 400.
