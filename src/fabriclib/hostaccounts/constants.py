"""The local root and administrator accounts of a DC's host (manual 1.6.13.6; decision 2.1.6.78)."""
RECORD = "local-accounts.json"              # <config>/local-accounts.json: the setup account and the approvals
ADMIN_GROUPS = ("sudo", "wheel", "admin")   # the groups that give sudo on Debian, Ubuntu and Red Hat (2.1.7.15)
PASSWD = "/etc/passwd"                      # local accounts only: the domain's (sssd) are never read here
GROUP = "/etc/group"
SUDOERS = "/etc/sudoers"
SUDOERS_DIR = "/etc/sudoers.d"
