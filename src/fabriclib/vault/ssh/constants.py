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
