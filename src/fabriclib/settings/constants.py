"""The setup wizard's settings and its file (manual 1.8.5, decision 2.1.8.7)."""
import re

FORMAT = 1                          # the settings file's `fabric_settings:` version

# the wizard's settings: what the web console's Settings and a settings file may change (manual 1.8.5.2). Everything
# else is console-only. DHCP (install_kea and its first subnet, dhcp) joins with the address manager in 0.9.0
# (2.1.1.58); until then it is setup's.
WIZARD_KEYS = ("dns_filter", "install_fluentbit", "log_forwarding", "host_ram_capacity",
               "ad_password_policy", "signin_kerberos", "logon_policies", "dns_filter_upstreams")

# the console-only settings the wizard's first step shows, read only, with the command that changes them
CONSOLE_ONLY = [
    ("domain", "the DNS domain: permanent", "sudo fabricctl setup (a new install)"),
    ("ad_domain", "the Windows (AD) domain: permanent", "sudo fabricctl setup (a new install)"),
    ("dc_name", "the domain controller's name: permanent", "sudo fabricctl setup (a new install)"),
    ("friendly_name", "the organisation's name, which names the CA: permanent", "sudo fabricctl setup (a new install)"),
    ("hostname", "this host's name", "sudo fabricctl setup, or the vars editor (sudo fabricctl)"),
    ("host_ip", "this host's LAN address", "sudo fabricctl setup, or the vars editor (sudo fabricctl)"),
    ("lan_cidr", "the LAN", "sudo fabricctl setup, or the vars editor (sudo fabricctl)"),
    ("lan_gateway", "the LAN's router", "sudo fabricctl setup, or the vars editor (sudo fabricctl)"),
    ("webui_admin_user", "the first admin", "chosen once by setup"),
    ("webui_client_cert", "the web console's client certificate", "sudo fabricctl security (raised on the Security "
                                                                  "page)"),
]

# the sub-keys of log_forwarding that name something on the host (a file it reads, names it resolves): console-only,
# kept as they are by an apply from the wizard or a file
LOG_HOST_KEYS = {"syslog": ("ca_file",), "elastic": ("ca_file",), "": ("hosts",)}

# a key of a settings file that holds a secret (never exported, ignored on import)
SECRET_RE = re.compile(r"(password|passphrase|secret|token|psk|_keys?$|^tsig)", re.I)

# the reasons an import lists for a key it ignored (manual 1.8.5.4)
CONSOLE = "console only"
SECRET = "a secret"
UNKNOWN = "not a setting"

# where the wizard records that it has been applied once or dismissed (beside vars.yaml)
STATE_FILE = "settings-wizard.json"

PLAN_TTL = 900                      # seconds a plan may wait for its Apply
