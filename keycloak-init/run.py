from keycloak.keycloak_admin import KeycloakAdmin, KeycloakPostError
from kubernetes import client as k8s, config as k8s_config
import base64
import yaml
import os
import subprocess
import time
from typing import Optional

# Load in-cluster configuration for Kubernetes client
k8s_config.load_incluster_config()


# Load globals and env vars to use
# -------------------------------------- #
#           KEYCLOAK GLOBALS             #
# -------------------------------------- #
KEYCLOAK_ADMIN = os.getenv("KEYCLOAK_ADMIN")
KEYCLOAK_ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD")
KEYCLOAK_ADMIN_EMAIL = os.getenv("KEYCLOAK_ADMIN_EMAIL", "admin@wisefood.gr")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "master")
KEYCLOAK_PORT = os.getenv("KEYCLOAK_PORT", "8080")
KEYCLOAK_PROTO = os.getenv("KEYCLOAK_PROTO", "http")  # prefer https in production
KEYCLOAK_URL = f"{KEYCLOAK_PROTO}://keycloak:{KEYCLOAK_PORT}"
KEYCLOAK_DOMAIN = os.getenv("KEYCLOAK_DOMAIN", "https://auth.wisefood.gr")

# -------------------------------------- #
#              K8s GLOBALS               #
# -------------------------------------- #
KUBE_NAMESPACE = os.getenv("KUBE_NAMESPACE", "default")


# -------------------------------------- #
#           KEYCLOAK ENV VARS            #
# -------------------------------------- #

# Client Names
MINIO_CLIENT = os.getenv("KC_MINIO_CLIENT_ID", "minio")
PUBLIC_CLIENT = os.getenv("KC_PUBLIC_CLIENT_ID", "wisefood-ui")
PRIVATE_CLIENT = os.getenv("KC_PRIVATE_CLIENT_ID", "wisefood-api")

# Client Redirects
MINIO_REDIRECT = os.getenv("MINIO_REDIRECT", "https://s3.wisefood.gr/oauth_callback")
PUBLIC_REDIRECT = os.getenv("PUBLIC_REDIRECT", "https://wisefood.gr:3000/*")
PRIVATE_REDIRECT = os.getenv("PRIVATE_REDIRECT", "")  # API is non-interactive; keep empty

# Client Valid Origins
MINIO_ORIGIN = os.getenv("MINIO_ORIGIN", "https://s3.wisefood.gr")
PUBLIC_ORIGIN = os.getenv("PUBLIC_ORIGIN", "https://wisefood.gr:3000")
PRIVATE_ORIGIN = os.getenv("PRIVATE_ORIGIN", "")  # API is non-interactive; keep empty

# MinIO
MINIO_API_DOMAIN = os.getenv("MINIO_API_DOMAIN", "https://s3.wisefood.gr")
MINIO_INTERNAL_DOMAIN = os.getenv("MINIO_INTERNAL_DOMAIN", "http://minio:9000")
MINIO_ROOT = os.getenv("MINIO_ROOT")
MINIO_ROOT_PASSWORD = os.getenv("MINIO_ROOT_PASSWORD")
MINIO_CATALOG_BUCKET = os.getenv("MINIO_CATALOG_BUCKET", "catalog")

# Misc
VERIFY_TLS = KEYCLOAK_PROTO == "https"

def initialize_keycloak_admin() -> KeycloakAdmin:
    """
    Initialize the Keycloak Admin client.
    """
    try:
        kc = KeycloakAdmin(
            server_url=KEYCLOAK_URL,
            username=KEYCLOAK_ADMIN,
            password=KEYCLOAK_ADMIN_PASSWORD,
            realm_name=KEYCLOAK_REALM,
            verify=VERIFY_TLS,
        )
        # Verify connection by fetching the realm
        kc.get_realm(KEYCLOAK_REALM)
        return kc
    except Exception as e:
        raise RuntimeError(f"Failed to initialize Keycloak Admin: {e}")


# Instantiate a single Keycloak Admin
K_ADMIN = initialize_keycloak_admin()


# ---- Keycloak Helpers ------------------------------------------------


def get_client_internal_id(keycloak_admin: KeycloakAdmin, client_id_str: str) -> Optional[str]:
    """
    Resolve the internal UUID for a clientId in a way that works across python-keycloak versions.
    """
    try:
        uuid = keycloak_admin.get_client_id(client_id_str)  
        if uuid:
            return uuid
    except Exception:
        pass

    # Fallback for very old versions (no get_client_id or it behaves differently)
    try:
        clients = keycloak_admin.get_clients(clientId=client_id_str)
        return clients[0]["id"] if clients else None
    except Exception:
        return None


def create_or_update_client(keycloak_admin: KeycloakAdmin, representation: dict) -> str:
    """
    Idempotently create or update a client by clientId; returns internal client UUID.
    """
    client_id_str = representation["clientId"]
    internal_id = get_client_internal_id(keycloak_admin, client_id_str)
    if internal_id:
        keycloak_admin.update_client(internal_id, representation)
    else:
        internal_id = keycloak_admin.create_client(representation, skip_exists=True)

    # Store the client secret back in Kubernetes secret if applicable
    if internal_id and not representation.get("publicClient", False):
        secret = keycloak_admin.get_client_secrets(internal_id)
        secret_value = secret.get("value") if secret else None
        if secret_value:
            secret_name = f"kc-{client_id_str}-secret"
            secret_obj = create_k8s_secret(
                secret_name=secret_name,
                namespace=KUBE_NAMESPACE,
                data_dict={"secret": secret_value},
            )
            try:
                apply_secret_to_cluster(secret_obj)
            except k8s.exceptions.ApiException as e:
                if e.status == 409:
                    print(f"Secret '{secret_name}' already exists. Skipping creation.")
                else:
                    print(f"Failed to apply secret '{secret_name}': {e}")
    return internal_id


def create_realm_role(keycloak_admin: KeycloakAdmin, role_name: str):
    """
    Create a realm role in Keycloak.
    """
    realm_role = {
        "name": role_name,
        "composite": True,
        "clientRole": False,
        "containerId": KEYCLOAK_REALM,
    }
    try:
        keycloak_admin.create_realm_role(realm_role, skip_exists=True)
    except KeycloakPostError:
        pass
    return role_name


def ensure_client_roles(keycloak_admin: KeycloakAdmin, client_id_str: str, roles=("read", "write")):
    """
    Ensure that the specified client roles exist for a given client.
    """
    internal_id = get_client_internal_id(keycloak_admin, client_id_str)
    for role in roles:
        try:
            keycloak_admin.create_client_role(internal_id, {"name": role})
        except KeycloakPostError:
            pass


def enable_service_account(keycloak_admin: KeycloakAdmin, client_id: str):
    """
    Enable service account for a given client and assign the admin role.
    This only applies to private clients, such that they are able to 
    perform admin tasks programmatically. (e.g. MinIO, WiseFood-API etc.)
    """
    try:
        # Retrieve the client configuration
        client_representation = keycloak_admin.get_client(client_id)

        # Update the configuration to enable service accounts
        client_representation["serviceAccountsEnabled"] = True
        client_representation["authorizationServicesEnabled"] = True

        # Update the client with the modified configuration
        keycloak_admin.update_client(client_id, client_representation)
        print(f"Service account enabled for client with ID: {client_id}")

        role = keycloak_admin.get_realm_role("admin")
        print(f"Retrieved existing role: {role}")

        service_account_user = keycloak_admin.get_client_service_account_user(client_id)
        service_account_user_id = service_account_user["id"]

        # Assign the admin role to the service account user
        keycloak_admin.assign_realm_roles(service_account_user_id, [role])
        print(f"Admin role assigned to service account for client ID: {client_id}")

    except KeycloakPostError as e:
        print(f"Failed to enable service account: {e}")
        raise

# Function creating a keycloak client scope
def create_client_scope(
    keycloak_admin: KeycloakAdmin,
    client_id,
    name,
    claim_name,
    mapper_name,
    mapper_type="oidc-usermodel-client-role-mapper",
    attribute_name=None,
    type="String",
    multivalued="true",
    audience_client_id: Optional[str] = None,
    add_to_id_token: str = "true",
    add_to_access_token: str = "true",
):
    """
    Create a client scope with a single protocol mapper and attach it as a DEFAULT scope to the given client.

    Compatibility notes:
    - For 'oidc-usermodel-client-role-mapper' and 'oidc-usermodel-attribute-mapper', 'claim_name' is used.
    - For 'oidc-usermodel-attribute-mapper', set 'attribute_name'.
    - For 'oidc-audience-mapper', ignore 'claim_name' and set 'audience_client_id' to the API/client you want in 'aud'.
    - MinIO typically reads ID Token, so keep 'add_to_id_token' = "true" for MinIO-related claims.
      For API access enforcement, prefer 'add_to_access_token' = "true" and often set ID token to "false".
    """
    # Build base mapper config
    protocol_mapper = {
        "name": mapper_name,
        "protocol": "openid-connect",
        "protocolMapper": mapper_type,
        "consentRequired": False,
        "config": {
            "id.token.claim": add_to_id_token,
            "access.token.claim": add_to_access_token,
            "multivalued": multivalued,
        },
    }

    if mapper_type == "oidc-audience-mapper":
        if not audience_client_id:
            raise ValueError("audience_client_id is required for oidc-audience-mapper")
        protocol_mapper["config"]["included.client.audience"] = audience_client_id
    else:
        protocol_mapper["config"]["claim.name"] = claim_name
        protocol_mapper["config"]["jsonType.label"] = type

        if mapper_type == "oidc-usermodel-client-role-mapper":
            protocol_mapper["config"]["user.attribute"] = attribute_name
            protocol_mapper["config"]["userinfo.token.claim"] = "true"

    # Create or get scope
    scope = {"name": name, "protocol": "openid-connect"}
    try:
        client_scope_id = keycloak_admin.create_client_scope(scope)
    except KeycloakPostError:
        # If already exists, find it
        existing = next((s for s in keycloak_admin.get_client_scopes() if s["name"] == name), None)
        client_scope_id = existing["id"] if existing else None

    if not client_scope_id:
        raise RuntimeError(f"Unable to ensure client scope '{name}'")

    # Idempotently (re)create the mapper
    existing_mappers = keycloak_admin.get_mappers_from_client(client_id=client_id)
    for m in existing_mappers:
        if m["name"] == mapper_name:
            keycloak_admin.delete_mapper_from_client_scope(protocol_mapper_id=m["id"], client_scope_id=client_scope_id)
            break
    # Check if the mapper already exists before adding it
    existing_mappers = keycloak_admin.get_mappers_from_client_scope(client_scope_id)
    if not any(m["name"] == protocol_mapper["name"] for m in existing_mappers):
        keycloak_admin.add_mapper_to_client_scope(client_scope_id, protocol_mapper)

    # Attach as DEFAULT scope to the given client (client_id here is internal UUID)
    default_scopes = keycloak_admin.get_client_scopes()
    if name not in [s["name"] for s in default_scopes]:
        keycloak_admin.add_client_default_client_scope(client_id=client_id, client_scope_id=client_scope_id, payload={})

    return client_scope_id


def ensure_wisefood_api_scope(keycloak_admin: KeycloakAdmin, ui_internal_id: str, api_client_id_str: str):
    """
    Ensures the combined client scope 'wisefood-api-scope' is present with:
      - Audience mapper --> adds wisefood-api into 'aud' of access token
      - Client roles mapper --> emits resource_access.wisefood-api.roles
    Attaches as DEFAULT to wisefood-ui.
    """
    scope_name = "wisefood-api-scope"
    # 1) Ensure audience mapper (only access token)
    create_client_scope(
        keycloak_admin=keycloak_admin,
        client_id=ui_internal_id,
        name=scope_name,
        claim_name="",  # ignored for audience mapper
        mapper_name=f"Audience: {api_client_id_str}",
        mapper_type="oidc-audience-mapper",
        audience_client_id=api_client_id_str,
        add_to_id_token="false",
        add_to_access_token="true",
    )

    # 2) Ensure roles mapper (only access token)
    create_client_scope(
        keycloak_admin=keycloak_admin,
        client_id=ui_internal_id,
        name=scope_name,
        claim_name=f"resource_access.{api_client_id_str}.roles",
        mapper_name=f"Roles: {api_client_id_str}",
        mapper_type="oidc-usermodel-client-role-mapper",
        attribute_name=None,
        type="String",
        multivalued="true",
        add_to_id_token="false",
        add_to_access_token="true",
    )


# ---- MinIO Helpers ---------------------------------------------------


def run_mc(args: list[str]):
    """
    Run 'mc' with argument array and report the command output.
    """
    result = subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print(f"Command: {' '.join(args)}")
    print(f"Output: {result.stdout}")
    print(f"Error: {result.stderr}")
    return result


def minio_openid(keycloak_admin: KeycloakAdmin, client_id: str):
    """
    Create an OpenID configuration between Keycloak and MinIO.
    """
    # Base command for setting the alias
    # Using arg arrays to avoid shell quoting/injection
    run_mc(["mc", "alias", "set", "myminio", MINIO_INTERNAL_DOMAIN, MINIO_ROOT, MINIO_ROOT_PASSWORD])

    client_secret = keycloak_admin.get_client_secrets(client_id)
    client_secr_value = client_secret.get("value")

    config_url = f"{KEYCLOAK_DOMAIN}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration"

    # MinIO usually reads ID Token; we expose 'policy' claim via a user attribute mapper if needed.
    run_mc([
        "mc", "idp", "openid", "add", "myminio", "wisefood-sso",
        f"client_id={MINIO_CLIENT}",
        f"client_secret={client_secr_value}",
        f"config_url={config_url}",
        "claim_name=policy",
        'display_name=WiseFood SSO',
        "scopes=openid",
        f"redirect_uri={MINIO_REDIRECT}"
    ])

    # Restart MinIO service
    restart_command = "mc admin service restart myminio"
    subprocess.run(
        f'script -q -c "{restart_command}"', shell=True, check=True
    )


def create_bucket(bucket_name: str):
    # Create the bucket using MinIO client
    try:
        run_mc(["mc", "mb", f"myminio/{bucket_name}"])
        print(f"Bucket '{bucket_name}' created successfully.")
    except subprocess.CalledProcessError as e:
        # If already exists or other error, report minimally
        print(f"Failed to create bucket '{bucket_name}': {e}")


# ---- Kubernetes Helpers ----------------------------------------------


def create_k8s_secret(secret_name, namespace, data_dict):
    # Encode data to base64 as required by Kubernetes secrets
    encoded_data = {
        k: base64.b64encode(v.encode("utf-8")).decode("utf-8")
        for k, v in data_dict.items()
    }

    # Define the secret structure
    secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": secret_name,
            "namespace": namespace,
        },
        "type": "Opaque",
        "data": encoded_data,
    }

    # Output only metadata for verification (avoid dumping secret data)
    print(f"Prepared Kubernetes Secret '{secret_name}' for namespace '{namespace}'.")

    return secret


# Function to apply the secret to the Kubernetes cluster
def apply_secret_to_cluster(secret):
    # Initialize Kubernetes client
    v1 = k8s.CoreV1Api()

    # Create or replace the secret in the specified namespace
    try:
        v1.create_namespaced_secret(
            namespace=secret["metadata"]["namespace"], body=secret
        )
        print(
            f"Secret '{secret['metadata']['name']}' created in namespace '{secret['metadata']['namespace']}'."
        )
    except k8s.exceptions.ApiException as e:
        if e.status == 409:
            v1.replace_namespaced_secret(secret["metadata"]["name"], secret["metadata"]["namespace"], secret)
            print(f"Secret '{secret['metadata']['name']}' replaced in namespace '{secret['metadata']['namespace']}'.")
        else:
            print(f"Failed to create secret: {e}")



def configure_realm_settings(keycloak_admin: KeycloakAdmin):
    admin_id = keycloak_admin.get_user_id("admin")
    admin_rep = keycloak_admin.get_user(admin_id)
    admin_rep['firstName'] = 'WiseFood'
    admin_rep['lastName'] = 'Administrator'
    admin_rep['email'] = KEYCLOAK_ADMIN_EMAIL
    admin_rep['emailVerified'] = True
    keycloak_admin.update_user(admin_id, admin_rep)

    realm_rep = keycloak_admin.get_realm(KEYCLOAK_REALM)
    realm_rep["displayName"] = "WiseFood SSO"
    realm_rep["accessTokenLifespan"] = 10800
    realm_rep["loginTheme"] = "keycloakify-starter"
    keycloak_admin.update_realm(KEYCLOAK_REALM, realm_rep)
    

# ---- App wiring ------------------------------------------------------


def main():
    kc = K_ADMIN

    # --- wisefood-api (confidential resource server) ---
    api_rep = {
        "clientId": PRIVATE_CLIENT,
        "protocol": "openid-connect",
        "publicClient": False,
        "enabled": True,

        # Enable password grant 
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": True,
        "serviceAccountsEnabled": True,

        "redirectUris": [],
        "webOrigins": [],

        "clientAuthenticatorType": "client-secret",
        "attributes": {
            "client_credentials.use_refresh_token": "false",
            "backchannel.logout.session.required": "true",
            "backchannel.logout.revoke.offline.tokens": "false",
            "oidc.ciba.grant.enabled": "false",
            "oauth2.device.authorization.grant.enabled": "false"
        }
    }
    api_internal_id = create_or_update_client(kc, api_rep)

    # Ensure some API-scoped client roles exist
    ensure_client_roles(kc, PRIVATE_CLIENT, roles=("read", "write"))

    # Give wisefood-api **admin** by assigning the realm 'admin' role to its service account
    try:
        enable_service_account(kc, api_internal_id)  # uses your original function & comments
    except Exception as e:
        print(f"Assigning admin role to wisefood-api failed: {e}")

    # --- wisefood-ui (public SPA) ---
    ui_rep = {
        "clientId": PUBLIC_CLIENT,
        "protocol": "openid-connect",
        "publicClient": True,
        "enabled": True,

        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,

        "redirectUris": [PUBLIC_REDIRECT],
        "webOrigins": [PUBLIC_ORIGIN],

        "attributes": {
            "oauth.pkce.enforced": "true",
            "pkce.code.challenge.method": "S256",
            "use.refresh.tokens": "true",
            "client_credentials.use_refresh_token": "false",
            "backchannel.logout.session.required": "true",
            "backchannel.logout.revoke.offline.tokens": "false"
        }
    }
    ui_internal_id = create_or_update_client(kc, ui_rep)

    # --- client scope: wisefood-api-scope (aud + roles) ---
    ensure_wisefood_api_scope(kc, ui_internal_id, PRIVATE_CLIENT)

    # --- MinIO OIDC (if configured) ---
    if MINIO_ROOT and MINIO_ROOT_PASSWORD:
        minio_rep = {
            "clientId": MINIO_CLIENT,
            "protocol": "openid-connect",
            "publicClient": False,
            "enabled": True,

            "standardFlowEnabled": True,   # MinIO uses auth code flow
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": True,

            "redirectUris": [MINIO_REDIRECT],
            "webOrigins": [MINIO_ORIGIN],

            "clientAuthenticatorType": "client-secret",
        }
        minio_internal_id = create_or_update_client(kc, minio_rep)

        # expose a user attribute 'policy' in the ID token claim for MinIO
        try:
            create_client_scope(
                keycloak_admin=kc,
                client_id=minio_internal_id,
                name="minio_auth_scope",
                claim_name="policy",
                mapper_name="MinIO Policy Attribute",
                attribute_name="policy",  # user attribute 'policy'
                type="String",
                multivalued="true",
                audience_client_id=None,
                add_to_id_token="true",       # MinIO reads ID token
                add_to_access_token="true",
            )

            # Assign the scope to MinIO client
            kc.add_client_default_client_scope(minio_internal_id, kc.get_client_scopes(clientScopeName="minio_auth_scope")[0]["id"], payload={})
            kc.add_client_default_client_scope(api_internal_id, kc.get_client_scopes(clientScopeName="minio_auth_scope")[0]["id"], payload={})
        except Exception as e:
            print(f"MinIO scope creation skipped/failed: {e}")

        # Establish MinIO OIDC trust
        try:
            minio_openid(kc, minio_internal_id)
            create_bucket(MINIO_CATALOG_BUCKET)
            ensure_client_roles(kc, MINIO_CLIENT, roles=("readonly", "readwrite", "consoleAdmin"))
        except Exception as e:
            print(f"MinIO OIDC setup failed: {e}")
    
    configure_realm_settings(kc)

if __name__ == "__main__":
    main()
