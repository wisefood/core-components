"""Inject Slovene message bundles into the WiseFood Keycloak theme JAR.

Upstream Keycloak gained Slovene in Feb 2025 (PR #37012), after the 25.0 image
we deploy was cut, so the shipped base themes contain no `sl` at all. The
bundles are taken verbatim from keycloak/keycloak `resources-community`
(Apache-2.0) and re-escaped to match this theme's existing convention.

Two distinct problems, two distinct fixes:

  login/account -> the theme bundles its OWN full copy of every base key, so it
                   shadows base entirely. Slovene must be added INSIDE the jar
                   or the login page stays English.
  email         -> the realm sets no emailTheme, so emails resolve straight from
                   `base`. The jar has no email type at all, so we ADD one
                   (parent=base, sl only) purely to carry the Slovene bundle.
"""
import io
import os
import re
import shutil
import zipfile

SCRATCH = os.path.dirname(os.path.abspath(__file__))
JAR = os.path.join(SCRATCH, os.pardir, "theme", "wisefood-theme.jar")
THEME = "keycloakify-starter"

# Keys the upstream bundle does not carry (measured, see report). They stay
# English via the theme's own messages_en.properties rather than being guessed
# at by a non-native speaker.
UNTRANSLATED_NOTE = (
    "# Slovene (sl) message bundle.\n"
    "#\n"
    "# Source: keycloak/keycloak, themes/src/main/resources-community/theme/base/\n"
    "#         <type>/messages/messages_sl.properties (Apache-2.0).\n"
    "# Imported because the deployed Keycloak 25.0 image predates upstream's\n"
    "# Slovene support and therefore ships none.\n"
    "#\n"
    "# Escaped to \\uXXXX to match the other bundles in this theme.\n"
    "# Keys absent here fall back to messages_en.properties by design.\n"
)


def parse(text):
    """Minimal .properties reader: keeps order, joins line continuations."""
    out = []
    buf = None
    for raw in text.splitlines():
        line = raw
        if buf is not None:
            buf += "\n" + line
            if not line.endswith("\\"):
                out.append(buf)
                buf = None
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("!"):
            continue
        if "=" not in line:
            continue
        if line.endswith("\\"):
            buf = line
        else:
            out.append(line)
    if buf is not None:
        out.append(buf)
    return out


def key_of(entry):
    return entry.partition("=")[0].strip()


def escape_ascii(text):
    """Escape non-ASCII to \\uXXXX, matching this theme's existing bundles."""
    return re.sub(r"[^\x00-\x7f]", lambda m: "\\u%04x" % ord(m.group()), text)


def read_jar_text(zf, path):
    return zf.read(path).decode("utf8")


def main():
    additions = {}

    with zipfile.ZipFile(JAR) as zf:
        names = set(zf.namelist())

        # ---- login + account: add messages_sl and register it in locales= ----
        # The account theme here is Account Console v3, whose key set differs
        # from the old base/account bundle; take its Slovene from the matching
        # account-ui community resources instead.
        sources = {"login": "sl_login.properties", "account": "sl_account_v3.properties"}
        for kind in ("login", "account"):
            src = os.path.join(SCRATCH, sources[kind])
            with io.open(src, encoding="utf8") as fh:
                entries = parse(fh.read())

            en_path = "theme/%s/%s/messages/messages_en.properties" % (THEME, kind)
            needed = {key_of(e) for e in parse(read_jar_text(zf, en_path))}
            have = {key_of(e) for e in entries}

            # Keep only keys this theme actually renders.
            kept = [e for e in entries if key_of(e) in needed]
            missing = sorted(needed - have)

            body = UNTRANSLATED_NOTE + "\n" + escape_ascii("\n".join(kept)) + "\n"
            additions["theme/%s/%s/messages/messages_sl.properties" % (THEME, kind)] = body
            print("%-8s kept %d/%d keys, %d fall back to English"
                  % (kind, len(kept), len(needed), len(missing)))

        # ---- email: the jar has no email type; create one carrying sl ----
        src = os.path.join(SCRATCH, "sl_email.properties")
        with io.open(src, encoding="utf8") as fh:
            email_entries = parse(fh.read())
        additions["theme/%s/email/messages/messages_sl.properties" % THEME] = (
            UNTRANSLATED_NOTE + "\n" + escape_ascii("\n".join(email_entries)) + "\n"
        )
        # parent=base so every other locale and all templates come from Keycloak.
        additions["theme/%s/email/theme.properties" % THEME] = (
            "parent=base\n"
            "\n"
            "# Exists solely to carry the Slovene bundle: Keycloak 25.0 ships no sl\n"
            "# email messages, and the realm otherwise resolves emails from base.\n"
            "locales=en,sl\n"
        )
        print("email    added %d keys + theme.properties (parent=base)" % len(email_entries))

    # ---- rewrite: copy every existing entry, patch locales=, append new ----
    # Built alongside the jar and moved into place only on success, so a failure
    # never leaves a half-written theme. _run() cleans the temp file up if any
    # of the guards below abort.
    tmp = JAR + ".tmp"
    patched_locales = []
    patched_manifest = False
    with zipfile.ZipFile(JAR) as zin, zipfile.ZipFile(
        tmp, "w", zipfile.ZIP_DEFLATED
    ) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename in additions:
                # The theme ships 0-byte messages_sl stubs for account/admin
                # while listing sl in locales= — which is why Slovene looked
                # available but rendered English. Replacing them is the point.
                if data:
                    raise SystemExit(
                        "refusing to overwrite non-empty %s" % item.filename
                    )
                print("replacing empty stub: %s" % item.filename)
                continue

            # Declare the new email type, or Keycloak ignores the directory
            # entirely and keeps resolving emails from `base`.
            if item.filename == "META-INF/keycloak-themes.json":
                import json as _json
                manifest = _json.loads(data.decode("utf8"))
                for entry in manifest.get("themes", []):
                    if entry.get("name") == THEME and "email" not in entry["types"]:
                        entry["types"] = sorted(entry["types"] + ["email"])
                        patched_manifest = True
                data = (_json.dumps(manifest, indent=2) + "\n").encode("utf8")

            # Add sl to the locales list of the login/account theme.properties.
            m = re.match(
                r"^theme/%s/(login|account)/theme\.properties$" % re.escape(THEME),
                item.filename,
            )
            if m:
                text = data.decode("utf8")
                def add_sl(mo):
                    vals = [v for v in mo.group(1).split(",") if v]
                    if "sl" in vals:
                        return mo.group(0)
                    vals.append("sl")
                    # Keycloak does not care about order; keep it sorted+stable.
                    return "locales=" + ",".join(sorted(vals))
                new_text, n = re.subn(r"locales=([^\n]*)", add_sl, text)
                if n:
                    patched_locales.append(m.group(1))
                    data = new_text.encode("utf8")

            zout.writestr(item, data)

        for path, body in sorted(additions.items()):
            zout.writestr(path, body.encode("utf8"))

    shutil.move(tmp, JAR)
    print("\npatched locales= in: %s" % ", ".join(patched_locales))
    print("declared email theme type: %s" % patched_manifest)
    print("added %d files to %s" % (len(additions), JAR))


def _run():
    """Run main(), removing the scratch jar if it aborted part-way."""
    tmp = JAR + ".tmp"
    try:
        main()
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


if __name__ == "__main__":
    _run()
