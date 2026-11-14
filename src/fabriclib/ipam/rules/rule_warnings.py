from fabriclib.ipam.rules.constants import ANY, EXTERNAL, FABRIC, HOST, SERVICES, SITE
from fabriclib.ipam.rules.decide_rule import decide_rule
from fabriclib.ipam.rules.network_names import network_names


def rule_warnings(rules, nets):
    """Purpose: what a rule list allows that is likely a mistake, said and taken (manual 1.10.4.48.5): a rule that
             never decides anything (one before it always does, or its source has no network yet), a rule that
             opens a service to every address (`any`, decision 2.1.10.62), a VLAN given DHCP but not DNS (its
             clients are handed fabric's DNS, which will not answer them), a VLAN allowed nothing.
    Inputs:  rules — the list as it will be; nets — rule_networks' result for the site.
    Returns: list of str.
    Fails:   never.
    Feeds:   change_rules, ipam/rules/show_rules, ipam/rules/rules_view."""
    out = []
    names = {c: network_names(c, nets) for c in nets["all"]}
    for n, rule in enumerate(rules, 1):
        covered = [c for c, these in names.items() if rule["from"] in these]
        if not covered:
            why = {HOST: "the host's network is not known here (no VLAN holds host_ip, and no lan_cidr)",
                   SITE: "the site has no network yet", FABRIC: "no site has a network yet"}.get(
                rule["from"], f"{'subnet' if '/' in rule['from'] else 'VLAN'} {rule['from']} has no network here")
            out.append(f"rule {n} (from {rule['from']}) matches no network yet: {why}")
            continue
        services = list(SERVICES) if rule["service"] == ANY else [rule["service"]]
        decided = [(c, s) for c in covered for s in services if not decide_rule(rules[:n - 1], names[c], s)[1]]
        if not decided:
            out.append(f"rule {n} never decides anything: the rules before it already decide every case it covers")
        elif rule["from"] == ANY and rule["action"] == "allow" and any(c == EXTERNAL for c, _ in decided):
            opened = sorted({s for c, s in decided if c == EXTERNAL}, key=list(SERVICES).index)
            out.append(f"rule {n} opens {', '.join(opened)} to every address, outside ones too")
    for ref, cidrs in nets["vlans"].items():
        if not cidrs:
            continue
        allowed = {s for s in SERVICES if any(decide_rule(rules, names[c], s)[0] == "allow" for c in cidrs)}
        if "dhcp" in allowed and "dns" not in allowed:
            out.append(f"VLAN {ref} gets DHCP from fabric but not DNS: its clients are handed fabric's DNS, which "
                       "will not answer them")
        if not allowed:
            out.append(f"VLAN {ref} reaches none of fabric's services: every request from it goes unanswered")
    return out
