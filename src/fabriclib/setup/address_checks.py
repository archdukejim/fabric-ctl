from fabriclib.common.dns_query import dns_query

HOSTS = "/etc/hosts"


def _hosts_lines(name, path):
    """Purpose: the addresses /etc/hosts gives a name.
    Inputs:  name — the name; path — the hosts file.
    Returns: list of str, one per line naming it (comments ignored); [] when the file is absent.
    Fails:   OSError other than a missing file.
    Feeds:   address_checks."""
    try:
        with open(path) as f:
            text = f.read()
    except FileNotFoundError:
        return []
    out = []
    for line in text.splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) > 1 and name.lower() in (f.lower() for f in fields[1:]):
            out.append(fields[0])
    return out


def address_checks(v, port=53, query=dns_query, hosts=HOSTS):
    """Purpose: doctor's checks that only the host's own address and name are left after a move or a rename
             (decision 2.1.1.74, known issue 2.3.1.34, manual 4.2.4.7): fabric's names in the site's zone answer the
             host's address alone; the domain controller's name answers it alone and the AD domain names it; and
             /etc/hosts names the DC at most once, at that address.
    Inputs:  v — the settings (hostname, domain, host_ip, hostname_stepca, hostname_dc, ad_domain, dns_fabric_own);
             port — BIND's port on the host's address; query — dns_query (a test's stand-in); hosts — /etc/hosts.
    Returns: list of (name, passed: bool, detail: str); a DNS error is a failed check naming it.
    Fails:   never.
    Feeds:   setup/verify_install (fabricctl doctor and the console's Overview)."""
    ip = str(v["host_ip"])
    rows = []

    def exact(name, label):
        try:
            got = query(name, ip, port)
        except OSError as e:
            rows.append((f"DNS {name}: {label} at {ip} only (2.1.1.74)", False, str(e)))
            return
        rows.append((f"DNS {name}: {label} at {ip} only (2.1.1.74)", got == [ip],
                     ", ".join(got) or "no answer"))

    domain = str(v["domain"])
    own_a = {str(r.get("name")) for r in ((v.get("dns_fabric_own") or {}).get("A") or []) if isinstance(r, dict)}
    exact(f"{v['hostname']}.{domain}".lower(), "this host")
    if "@" in own_a:                                   # fabric's @ (an admin's own @ is theirs to point anywhere)
        exact(domain, "the site's domain")
    exact(v["hostname_stepca"], "fabric's alias")
    if v.get("ad_domain") and v.get("hostname_dc"):
        exact(v["hostname_dc"], "the domain controller")
        try:
            got = query(str(v["ad_domain"]), ip, port)
            rows.append((f"DNS {v['ad_domain']}: the AD domain names this DC's address {ip} (2.1.1.74)", ip in got,
                         ", ".join(got) or "no answer"))
        except OSError as e:
            rows.append((f"DNS {v['ad_domain']}: the AD domain names this DC's address {ip} (2.1.1.74)", False,
                         str(e)))
        lines = _hosts_lines(str(v["hostname_dc"]), hosts)
        rows.append((f"/etc/hosts: {v['hostname_dc']} at most once, at {ip} (2.1.1.74)",
                     len(lines) <= 1 and all(a == ip for a in lines),
                     ", ".join(lines) or "not named (found by DNS)"))
    return rows
