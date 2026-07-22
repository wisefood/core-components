# Slovene theme patch

Adds Slovene to `../theme/wisefood-theme.jar`. Run from this directory:

```sh
python3 build_sl_theme.py
```

The script edits the jar **in place** and is guarded: it refuses to overwrite a
non-empty `messages_sl.properties`, so re-running an already-patched jar is a
no-op that exits without changing anything. To re-apply from scratch, restore
the jar with `git checkout ../theme/wisefood-theme.jar` first.

See `../README.md` for why this exists, what it changes, and how to verify the
result against a running Keycloak.

## Sources

The `sl_*.properties` files are unmodified copies from
[keycloak/keycloak](https://github.com/keycloak/keycloak) (Apache-2.0):

| File | Upstream path |
|---|---|
| `sl_login.properties` | `themes/src/main/resources-community/theme/base/login/messages/messages_sl.properties` |
| `sl_email.properties` | `themes/src/main/resources-community/theme/base/email/messages/messages_sl.properties` |
| `sl_account_v3.properties` | `js/apps/account-ui/maven-resources-community/theme/keycloak.v3/account/messages/messages_sl.properties` |

They are vendored because the deployed Keycloak 25.0 predates upstream Slovene
support, so the running server cannot supply them itself. If Keycloak is ever
upgraded past 26.2, most of this patch becomes redundant — the base themes will
carry `sl` on their own, and only the theme's own bundled copies would still
need it.

The script re-escapes them to `\uXXXX` to match the jar's existing bundles.
