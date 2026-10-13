"""OpenBao paths and names fabric uses."""
SLOT_STORE = "slots.json"                  # unlock methods (key slots), root 0600, signed with the vault key
KEY_FILE = "unseal.key"                    # iteration-1 layout (a bare key file); migrated into a local slot
SETUP_CREDS = "setup-approle.json"         # AppRole for fabricctl setup (root 0400)
AGENT_CREDS = "agent-approle.json"         # AppRole for fabric-agent (root 0400)
BOOTSTRAP_TOKEN = "bootstrap-root-token"   # initial root token, only until configure succeeds and revokes it
KV_MOUNTS = {"fabric/": "fabric's own secrets", "apps/": "secrets for your applications"}

# Policies written by configure_openbao (HCL). fabric-setup administers
# fabric's configuration; fabric-agent only reads status for the web UI.
POLICIES = {
    "fabric-setup": """
path "sys/mounts"          { capabilities = ["read"] }
path "sys/mounts/*"        { capabilities = ["create", "read", "update"] }
path "sys/auth"            { capabilities = ["read"] }
path "sys/auth/*"          { capabilities = ["create", "read", "update", "sudo"] }
path "sys/policies/acl/*"  { capabilities = ["create", "read", "update", "delete", "list"] }
path "auth/approle/role/*" { capabilities = ["create", "read", "update", "list"] }
path "fabric/*"            { capabilities = ["create", "read", "update", "delete", "list"] }
path "auth/oidc/*"         { capabilities = ["create", "read", "update", "delete", "list"] }
path "identity/group"      { capabilities = ["create", "update"] }
path "identity/group/*"    { capabilities = ["create", "read", "update", "delete", "list"] }
path "identity/group-alias"   { capabilities = ["create", "update"] }
path "identity/group-alias/*" { capabilities = ["create", "read", "update", "list"] }
path "database/config/*"   { capabilities = ["create", "read", "update"] }
path "database/static-roles/*" { capabilities = ["create", "read", "update"] }
path "database/static-creds/*" { capabilities = ["read"] }
path "database/rotate-role/*"  { capabilities = ["update"] }
path "ssh/*"               { capabilities = ["create", "read", "update", "delete", "list"] }
""",
    "fabric-agent": """
path "sys/mounts" { capabilities = ["read"] }
path "sys/auth"   { capabilities = ["read"] }
path "apps/metadata/*" { capabilities = ["list"] }
path "fabric/metadata/secrets" { capabilities = ["read"] }
""",
    # People who sign in with Keycloak (the web UI admin role): their
    # applications' secrets, and a read-only look at the configuration.
    # fabric's own secrets are listed, never read: that stays with
    # `sudo fabricctl secrets show` (audited on the host).
    "fabric-console-admin": """
path "apps/*"                 { capabilities = ["create", "read", "update", "patch", "delete", "list"] }
path "fabric/metadata"        { capabilities = ["list"] }
path "fabric/metadata/*"      { capabilities = ["list"] }
path "sys/mounts"             { capabilities = ["read"] }
path "sys/auth"               { capabilities = ["read"] }
path "sys/policies/acl"       { capabilities = ["list"] }
path "sys/policies/acl/*"     { capabilities = ["read"] }
path "sys/internal/ui/mounts" { capabilities = ["read"] }
path "sys/internal/ui/mounts/*" { capabilities = ["read"] }
""",
    # The auditor bundle: which application secrets exist and their history,
    # never a value; the configuration read-only.
    "fabric-auditor": """
path "apps/metadata"          { capabilities = ["list"] }
path "apps/metadata/*"        { capabilities = ["read", "list"] }
path "fabric/metadata"        { capabilities = ["list"] }
path "sys/mounts"             { capabilities = ["read"] }
path "sys/auth"               { capabilities = ["read"] }
path "sys/policies/acl"       { capabilities = ["list"] }
path "sys/policies/acl/*"     { capabilities = ["read"] }
path "sys/internal/ui/mounts" { capabilities = ["read"] }
path "sys/internal/ui/mounts/*" { capabilities = ["read"] }
""",
}

# fabric role bundle (Keycloak `roles` claim) -> OpenBao policy, through an
# external identity group per bundle. "admin" is the web UI admin role.
# Bundles not listed here cannot sign in to OpenBao.
OIDC_BUNDLE_POLICIES = {"admin": "fabric-console-admin", "fabric-auditor": "fabric-auditor"}
# names before 0.6.4, removed by setup: fabric-admin is now the first admin's user name (2.1.6.33)
RETIRED_NAMES = ("fabric-admin",)

# Sign-in for people: OpenBao's OIDC auth at auth/oidc, a Keycloak client of
# its own, one role bound to the web UI admin role claim.
OIDC_MOUNT = "oidc"
OIDC_CLIENT_ID = "fabric-openbao"
OIDC_ROLE = "people"
