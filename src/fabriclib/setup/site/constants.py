"""Names and limits of web-guided setup's temporary site (manual 1.3.6)."""

FIRST_PORT, LAST_PORT = 8443, 8453      # the host's TCP ports the site may claim, for setup's length only (1.3.6.7)
IDLE_SECONDS = 30 * 60                  # idle before Proceed: the site closes with nothing changed (1.3.6.3)
AFTER_SECONDS = 60 * 60                 # after setup ends: the site stops by itself (1.3.6.6)
WRONG_TRIES = 5                         # wrong codes before the code is replaced (1.3.6.3)
SESSION_IDLE_SECONDS = 15 * 60          # a session with no request and no open stream this long ends (2.1.8.62)
TICKET_SECONDS = 120                    # a takeover's confirmation is good this long, and once (2.1.8.62)
SITE_ID = 649                           # the listener's uid and gid: the top of fabric's band, no account (2.1.8.61)
CERT_DAYS = 1                           # the temporary certificate's life (1.3.6.3)
RULE_COMMENT = "fabric-setup-site"      # the ufw comment on the site's own rule: how fabric knows the rule is its own
PORT_RECORD = "/run/fabric-setup/site-port"     # tmpfs, root 0700: the site's port while it runs
ATTACH_SOCKET = "/run/fabric-setup/site-attach.sock"    # root's only: another terminal attaches to setup (2.1.8.60)
MINTED_NAME = "setup-site"              # the artifact files' name while the site's certificate is minted
