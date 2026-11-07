"""Names and limits of web-guided setup's temporary site (manual 1.3.6)."""

FIRST_PORT, LAST_PORT = 8443, 8453      # the host's TCP ports the site may claim, for setup's length only (1.3.6.7)
IDLE_SECONDS = 30 * 60                  # idle before Proceed: the site closes with nothing changed (1.3.6.3)
AFTER_SECONDS = 60 * 60                 # after setup ends: the site stops by itself (1.3.6.6)
WRONG_TRIES = 5                         # wrong codes before the code is replaced (1.3.6.3)
SESSION_QUIET_SECONDS = 120             # a session silent this long no longer keeps a second browser out (1.3.6.5)
CERT_DAYS = 1                           # the temporary certificate's life (1.3.6.3)
RULE_COMMENT = "fabric-setup-site"      # the ufw comment on the site's own rule: how fabric knows the rule is its own
PORT_RECORD = "/run/fabric-setup/site-port"     # tmpfs, root 0700: the site's port while it runs
MINTED_NAME = "setup-site"              # the artifact files' name while the site's certificate is minted
