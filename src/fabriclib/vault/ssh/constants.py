"""OpenBao's SSH certificate authority for the fabric admins (manual 1.6.11.9; decisions 2.1.7.5, 2.1.6.39,
2.1.7.12)."""
MOUNT = "ssh"                       # the SSH secrets engine's path
ROLE = "fabric-admin"               # the one signing role: user certificates only
TTL = "8h"                          # a certificate's life (2.1.7.5)
CA_KEY_TYPE = "ed25519"             # made inside OpenBao, never leaving it
PUBLISHED = "ssh-user-ca.pub"       # in nginx's www/certs/: https://<host's own name>/certs/ssh-user-ca.pub
MIN_RSA_BITS = 3072
# key types accepted for signing (OpenSSH names); everything else (DSA, certificates) is refused
KEY_TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa",
             "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
ROLE_SETTINGS = {"key_type": "ca", "allow_user_certificates": True, "allow_host_certificates": False,
                 "allowed_users": "*", "default_extensions": {"permit-pty": ""}, "allowed_extensions": "permit-pty",
                 "ttl": TTL, "max_ttl": TTL, "allow_user_key_ids": True}

# SSH host certificates (manual 1.6.11.9.6 to 1.6.11.9.11; decision 2.1.7.13): a CA of their own, in a mount of its
# own (OpenBao's SSH engine holds one CA key per mount), so a host certificate is never signed by the user CA
HOST_MOUNT = "ssh-host"             # the host CA's SSH secrets engine
HOST_ROLE = "fabric-host"           # host certificates only
HOST_TTL = "720h"                   # 30 days
HOST_DAYS = 30
RENEW_DAYS = 10                     # signed again once fewer days than this are left
HOST_PUBLISHED = "ssh-host-ca.pub"  # in nginx's www/certs/: https://<host's own name>/certs/ssh-host-ca.pub
# the host key types signed (OpenSSH names); DSA and RSA below MIN_RSA_BITS are never signed
HOST_KEY_TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa")
# allowed_domains "*": the short name has no domain to match; fabric is the role's only caller and chooses every
# principal itself from the computer account (host_principals), never from what a machine asks for
HOST_ROLE_SETTINGS = {"key_type": "ca", "allow_user_certificates": False, "allow_host_certificates": True,
                      "allowed_domains": "*", "allow_subdomains": True, "allow_bare_domains": True,
                      "ttl": HOST_TTL, "max_ttl": HOST_TTL, "allow_user_key_ids": True}
