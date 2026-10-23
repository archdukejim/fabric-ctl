import ipaddress

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.ipam.common.plan_holds_subnets import MOVED, plan_holds_subnets
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp


def add_reservation(actor, mac, ip, hostname="", source="cli"):
    """Purpose: Reserve an IPv4 address for a MAC (optionally with a hostname) in the DHCP subnet that contains it, in
             vars.yaml. Applied by the next apply.
    Inputs:  actor — str, who asks (audit).
             mac — str, aa:bb:cc:dd:ee:ff or with dashes (normalized by normalize_dhcp).
             ip — str address inside one of dhcp.subnets (inside a pool too, since 0.9.0: 1.10.4.3.2).
             hostname — str, one DNS label; optional.
             source — "cli" (default) or "web". Reads/writes vars.yaml under vars_lock.
    Returns: the saved reservation {"mac", "ip", optional "hostname"}.
    Fails:   ValidationError MOVED once the subnets live in the address plan (1.10.4.37); ValidationError "… is not an
             IPv4 address" (unparseable), "… is in none of the DHCP subnets", or one from normalize_dhcp (bad MAC,
             inside a pool, duplicate MAC or address, bad hostname, a static A record in a pool); plain ValueError from
             normalize_dhcp if a stored router is not an address; OSError or yaml.YAMLError from vars_lock / load_vars /
             save_vars / write_audit.
    Feeds:   agent route POST /v1/dhcp/reservations (fabric-agent, src/agent/, called by the web UI);
             run_dhcp_command (reserve).
    Notes:   the whole `dhcp:` block is validated again (as if install_kea were on) before anything is saved.
    """
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        raise ValidationError(f"{ip!r} is not an IPv4 address")
    with vars_lock():
        data = load_vars()
        if plan_holds_subnets(data):          # the plan's since 0.9.0 (1.10.4.37): fabricctl ipam makes it
            raise ValidationError(MOVED)
        dhcp = data.get("dhcp") or {}
        subnet = next((s for s in dhcp.get("subnets") or []
                       if addr in ipaddress.ip_network(str(s.get("subnet")), strict=False)), None)
        if subnet is None:
            raise ValidationError(f"{addr} is in none of the DHCP subnets")
        entry = {"mac": str(mac).strip(), "ip": str(addr), **({"hostname": hostname.strip()} if hostname else {})}
        subnet.setdefault("reservations", []).append(entry)
        dhcp = normalize_dhcp({**data, "dhcp": dhcp, "install_kea": True})
        data["dhcp"] = dhcp
        save_vars(data)
    saved = next(r for s in dhcp["subnets"] for r in s["reservations"] if r["ip"] == str(addr))
    write_audit(actor, "DHCP_RESERVE", f"{saved}", source)
    return saved
