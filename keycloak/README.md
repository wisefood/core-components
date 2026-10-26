# Keycloak IdP Image

Keycloak 25.0 plus the WiseFood Keycloakify theme in `theme/wisefood-theme.jar`
and the WiseFood email theme in `themes/wisefood/`, baked in with `kc.sh build`
(see `Dockerfile`). `make build push` publishes `wisefood/keycloak:latest`.

## The WiseFood email theme (`themes/wisefood/email`)

Every email Keycloak sends — verification, password reset, "update your
account", the SMTP test, and its security alerts — goes out in the same frame
as the platform's own mail: the WiseFood logo on the site's warm background, a
white card, one button, and the consortium footer with the EU emblem.

* **It is a plain folder theme, readable in review**, inheriting
  `keycloakify-starter` (the jar), which in turn carries base plus the Slovene
  bundle. Nothing in the jar is touched.
* `html/template.ftl` is the frame. Base templates import `template.ftl`, which
  resolves to this theme's, so even emails this theme does not reword get the
  frame around Keycloak's own wording.
* Five emails are reworded with a real button and plain language, in en, hu, sl
  and el (`html/` and `text/` for each, `messages/messages_*.properties`):
  `email-verification`, `password-reset`, `executeActions`,
  `email-update-confirmation`, `email-test`. Subjects for those are overridden
  too. Other locales fall back to English wording inside the same frame.
* The frame mirrors `wisefood-api/src/email_layout.py`. **Change both
  together** — colours, spacing, footer.
* Images are absolute URLs (a mail cannot load Keycloak theme resources),
  read from the container's environment through `theme.properties`:
  `WISEFOOD_APP_URL`, `WISEFOOD_EMAIL_LOGO_URL`, `WISEFOOD_EMAIL_EU_URL`
  (set in platform-deployment's `keycloak.libsonnet`). The files themselves are
  the console's `public/email/`.
* Message bundles follow the jar's convention: `\uXXXX`-escaped, and Java
  MessageFormat rules apply — no bare single quotes.

The realm selects it with `emailTheme = wisefood` (keycloak-init, overridable
with `KEYCLOAK_EMAIL_THEME`), and sends as **"WiseFood"** rather than
"WiseFood SSO", so an inbox shows one sender for the whole service.

### Checking a change to the email theme

Folder themes are refused when their real path lies outside Keycloak's themes
directory, so **copy** the theme rather than symlinking it. With a Keycloak 25
distribution and a mail catcher (Mailpit on `:1025`/`:8025`):

```sh
cp -r themes/wisefood "$KC_HOME/themes/"
cp theme/wisefood-theme.jar "$KC_HOME/providers/"
KEYCLOAK_ADMIN=admin KEYCLOAK_ADMIN_PASSWORD=admin "$KC_HOME/bin/kc.sh" start-dev \
  --http-port=8099 --spi-theme-cache-themes=false --spi-theme-cache-templates=false
```

Set the realm's SMTP to the catcher and `emailTheme` to `wisefood`, give test
users a `locale` attribute, then trigger mails through the admin API
(`PUT /users/{id}/send-verify-email`, `PUT /users/{id}/execute-actions-email`,
`POST /testSMTPConnection`) and the login page's "Forgot password". Check the
subject and `<html lang>` follow the user's locale, that no `${env` survives in
the HTML, and look at the result at desktop and phone widths.

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
* `emailTheme` must be `wisefood` (which inherits `keycloakify-starter`), or
  emails lose the WiseFood frame; pointing it at `base` would also lose
  Slovene, which base lacks in 25.0.

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
