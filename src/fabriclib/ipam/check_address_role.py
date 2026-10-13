from fabriclib.common.errors import ValidationError
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def check_address_role(v, addr, subnet, site, roles=None, secrets=None, container="samba"):
    """Purpose: the device role a reservation names (MAB from a reservation, manual 1.11.1.7) checked against the
             directory: a role this site may use (its own or the organisation's) is required; one that does not grant
             network:mab, or whose VLAN is not the reservation's subnet's, is warned about (the policy puts the device
             on the subnet's VLAN). Another site's roles are not read here: its reservation is warned about instead.
    Inputs:  v — fabric vars (site_name); addr — check_address's normalized address
             ("role", "ip"); subnet — its subnet's plan entry ("vlan", "cidr"); site — the plan's site; roles —
             the roles this site may use (read_devices' "roles"; tests), default read from the DC; secrets — fabric's
             secrets for that read (default load_secrets()); container — the DC's container.
    Returns: list of str, warnings (empty for no role, or a role that fits).
    Fails:   ValidationError "no device role named <role> …"; run_op's errors (the DC not answering).
    Feeds:   add_address, set_address."""
    role = addr.get("role") or ""
    if not role:
        return []
    if site != v.get("site_name"):
        return [f"{addr['ip']}: the role {role} is {site}'s to check: its policy refuses the device if {site} has no "
                "such role"]
    if roles is None:
        secrets = secrets if secrets is not None else load_secrets()
        roles = run_op(v, secrets, "read_devices", container=container)["roles"]
    found = next((r for r in roles if r["name"] == role), None)
    if found is None:
        raise ValidationError(f"no device role named {role}: add it on the Directory tab (or name one of: "
                              f"{', '.join(r['name'] for r in roles) or 'none yet'})")
    warnings = []
    if "network:mab" not in (found.get("permissions") or []):
        warnings.append(f"the role {role} does not grant network:mab: the device at {addr['ip']} is refused by MAB "
                        "until it does")
    if found.get("vlan") and subnet.get("vlan") and found["vlan"] != subnet["vlan"]:
        warnings.append(f"the role {role} names VLAN {found['vlan']}, but {addr['ip']} is in {subnet['cidr']} "
                        f"(VLAN {subnet['vlan']}): the device is put on VLAN {subnet['vlan']}, where its address works")
    return warnings
