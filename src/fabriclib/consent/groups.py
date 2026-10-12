"""The kinds of host change fabric asks about (manual 1.2.9.3), in the order setup asks.

level: "required" — declining stops setup; "recommended" — declining leaves that part unmanaged and shows a
relaxation; "choice" — needed only because of a setting, declining asks for the other choice.
needs: a group asked only when that group was answered yes (2.1.2.13: the firewall's three questions)."""

GROUPS = {
    "packages": {"title": "Packages", "level": "required", "step": "host",
                 "declined": "setup cannot run without them"},
    "runtime": {"title": "Docker daemon settings", "level": "recommended", "step": "docker",
                "declined": "the Docker daemon is not hardened (containers may gain privileges via setuid "
                            "binaries; logs can fill the disk)"},
    "services": {"title": "fabric's own services", "level": "required", "step": "deploy",
                 "declined": "fabric cannot run without its services"},
    "accounts": {"title": "Service accounts", "level": "required", "step": "accounts",
                 "declined": "the services cannot own their files without them"},
    "resolver": {"title": "Host DNS resolver", "level": "choice", "step": "network",
                 "declined": "set use_host_dns: true (keep the host's resolver) and free port 53 another way"},
    "ports": {"title": "Ports fabric needs", "level": "recommended", "step": "firewall",
              "declined": "ufw is not told about fabric's ports: with ufw on, fabric's own containers cannot reach "
                          "this host's domain controller (setup stops); with ufw off, nothing changes"},
    "firewall": {"title": "Secure this host", "level": "recommended", "step": "firewall", "needs": "ports",
                 "declined": "the host firewall is not managed by fabric: every published port is reachable "
                             "from any network that can route to this host"},
    "own_rules": {"title": "The host's own firewall rules", "level": "recommended", "step": "firewall",
                  "needs": "firewall",
                  "declined": "the host's own rules stay: those ports stay open beside fabric's and SSH"},
    "trust": {"title": "Host trust store", "level": "recommended", "step": "pki",
              "declined": "this host does not trust fabric's CA: tools on the host (curl, apt, browsers) reject "
                          "fabric's certificates unless given the CA"},
    "time": {"title": "Time service (chrony)", "level": "recommended", "step": "deploy",
             "declined": "chrony keeps the host's own configuration: fabric does not serve time to the network "
                         "or follow the upstream site"},
    "member": {"title": "This host as a member of its domain", "level": "recommended", "step": "member",
               "declined": "this host is not a member of its domain: fabric admins sign in to it with local accounts "
                           "only, and sudo here does not follow the domain's rules"},
}

# A group later split into several (2.1.2.14): an install whose answers predate the split (it has no answer for
# the marker group) keeps its answer for each group the old one covered; groups that are new are asked as usual.
SPLITS = {
    "firewall": {"release": "0.6.2", "marker": "ports", "covered": ["ports", "firewall"]},   # own_rules: new
}
