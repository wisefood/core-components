# WiseFood Keycloak Init Utility Image

This utility configures Keycloak, MinIO OIDC, and Kubernetes secrets on startup. It’s designed to run as an **init container** in your cluster so your realm, clients, scopes, and integrations are ready before app pods start.

## What it does

* Connects to **Keycloak** (admin API) and idempotently:

  * Creates/updates two clients:

    * **`wisefood-ui`** (public SPA): Authorization Code + PKCE, no password grant.
    * **`wisefood-api`** (confidential API): service account enabled, **password grant enabled**, no browser flow.
  * Creates **`wisefood-api-scope`** and attaches it to the UI:

    * Adds audience `wisefood-api` to access tokens.
    * Emits roles under `resource_access.wisefood-api.roles`.
  * Ensures API client roles (`read`, `write`).
  * Grants **realm `admin`** to the **`wisefood-api`** service account.
* Configures **MinIO OIDC** against Keycloak (optional; enabled when MinIO env vars are provided).
* Creates a **Kubernetes Secret** with OIDC discovery endpoints for downstream apps.

> The script is **idempotent**: safe to run repeatedly.

---

## Repository layout

```
.
├─ Dockerfile
├─ Makefile
├─ README.md
├─ requirements.txt
└─ run.py
```

---

## Requirements

* Keycloak reachable at `keycloak:<port>` from the pod network.
* A Keycloak **admin user** (username/password).
* Kubernetes ServiceAccount/Pod with permissions to create/replace secrets in the target namespace.
* MinIO reachable by `mc` inside the container and MinIO root credentials.

---

## Configuration (Environment Variables)

| Variable                  | Description                      | Example / Default                          |
| ------------------------- | -------------------------------- | ------------------------------------------ |
| `KEYCLOAK_ADMIN`          | Keycloak admin username          | `admin`                                    |
| `KEYCLOAK_ADMIN_PASSWORD` | Keycloak admin password          | `***`                                      |
| `KEYCLOAK_ADMIN_EMAIL`    | Admin email (not critical)       | `admin@wisefood.gr`                        |
| `KEYCLOAK_REALM`          | Realm name to manage             | `master`                                   |
| `KEYCLOAK_PORT`           | Keycloak port                    | `8080`                                     |
| `KEYCLOAK_PROTO`          | `http` or `https`                | `http` (use `https` in prod)               |
| `KUBE_NAMESPACE`          | Namespace for the created secret | `default`                                  |
| `KC_PUBLIC_CLIENT_ID`     | UI clientId                      | `wisefood-ui`                              |
| `KC_PRIVATE_CLIENT_ID`    | API clientId                     | `wisefood-api`                             |
| `KC_MINIO_CLIENT_ID`      | MinIO clientId (confidential)    | `minio`                                    |
| `PUBLIC_REDIRECT`         | UI redirect URI                  | `https://wisefood.gr:3000/*`               |
| `PUBLIC_ORIGIN`           | UI web origin                    | `https://wisefood.gr:3000`                 |
| `PRIVATE_REDIRECT`        | API redirect (unused)            | *(empty)*                                  |
| `PRIVATE_ORIGIN`          | API web origin (unused)          | *(empty)*                                  |
| `MINIO_REDIRECT`          | MinIO redirect URI               | `https://minio.example.com/oauth_callback` |
| `MINIO_ORIGIN`            | MinIO web origin                 | `https://minio.example.com`                |
| `MINIO_API_DOMAIN`        | `mc` endpoint URL                | `https://minio.example.com`                |
| `MINIO_ROOT`              | MinIO access key                 | `***`                                      |
| `MINIO_ROOT_PASSWORD`     | MinIO secret key                 | `***`                                      |