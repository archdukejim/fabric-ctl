"""The fabric host's local-admin (manual 1.7.1.4)."""
import string

USER = "local-admin"                        # the managed account's name everywhere (2.1.7.11)
COMMENT = "fabric local-admin (OpenBao, break glass)"
RECORD = "local-admin.json"                 # <config>/local-admin.json (0600): what fabric made and what it saw
MOUNT = "local-admin"                       # OpenBao's KV v2 mount of its own (1.7.1.3.2)
KIND = "fabric-host"                        # the path's kind: <site>/<kind>/<machine>/<account>
MAX_VERSIONS = 10                           # kept for the audit; only the current one is valid (1.7.1.3.2)
PASSWORD_POLICY = "local-admin"             # OpenBao's password policy for every local-admin (1.7.1.4.2)
# 24 characters from letters and digits a person reads back from paper without doubt: no 0 O 1 l I (1.7.1.3.2)
UPPER = "".join(c for c in string.ascii_uppercase if c not in "OI")
LOWER = "".join(c for c in string.ascii_lowercase if c != "l")
DIGITS = "".join(c for c in string.digits if c not in "01")
PASSWORD_POLICY_HCL = f"""length = 24
rule "charset" {{
  charset = "{UPPER}"
  min-chars = 1
}}
rule "charset" {{
  charset = "{LOWER}"
  min-chars = 1
}}
rule "charset" {{
  charset = "{DIGITS}"
  min-chars = 1
}}
"""
POLICIES = ("after-use", "keep-until-checkout")    # 2.1.7.16; after-use the default
DEFAULT_POLICY = "after-use"
GRACE_HOURS = 8                             # a used or checked-out password is rotated this long after (1.7.1.3.4)
ADMIN_GROUPS = ("sudo", "wheel")            # the first that exists gives local-admin its sudo
# the SSH switch's drop-in (2.1.7.19): before fabric's 10-fabric.conf and Ubuntu's 50-cloud-init.conf
SSHD_DIR = "/etc/ssh/sshd_config.d"
SSHD_DROPIN = "/etc/ssh/sshd_config.d/05-fabric-local-admin.conf"
MARK = "# fabric (manual 1.7.1.4.6)"
WTMP = "/var/log/wtmp"
REASON_MAX = 200                            # a check-out's reason: one line, up to this many characters
