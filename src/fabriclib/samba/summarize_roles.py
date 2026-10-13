# samba-tool fsmo show's role names, said plainly (2.1.2.22 item 5): AD's five roles, then the two DNS partitions'
ROLE_NAMES = {"SchemaMasterRole": "schema master", "DomainNamingMasterRole": "domain naming master",
              "RidAllocationMasterRole": "RID master", "PdcEmulationMasterRole": "PDC emulator",
              "InfrastructureMasterRole": "infrastructure master",
              "DomainDnsZonesMasterRole": "domain DNS zone master",
              "ForestDnsZonesMasterRole": "forest DNS zone master"}


def _owner(value):
    """Purpose: the domain controller a role's owner names: the server's CN in an NTDS Settings DN
             ("CN=NTDS Settings,CN=DC-PI-CORE,CN=Servers,…" → "DC-PI-CORE"), or the value itself when it is no DN.
    Inputs:  value — str after "owner:".
    Returns: str.
    Fails:   never.
    Feeds:   summarize_roles."""
    parts = [p.strip() for p in value.split(",")]
    if len(parts) > 1 and parts[0].upper() == "CN=NTDS SETTINGS" and parts[1].upper().startswith("CN="):
        return parts[1][3:]
    return value.strip()


def summarize_roles(lines, dc):
    """Purpose: the domain-wide (FSMO) roles named plainly for the Directory tab's Domain section, not as each role's
             DN (2.1.2.22 item 5): whether this controller holds them all, or which it holds and which another does.
    Inputs:  lines — samba-tool fsmo show's lines ("SchemaMasterRole owner: CN=NTDS Settings,CN=<DC>,…");
             dc — this controller's name (hostname_dc: its first label is compared, case ignored).
    Returns: {"text": one sentence, "held": [plain role names], "elsewhere": [{"role", "dc"}]}; text is "" when no
             role could be read (the DC not running).
    Fails:   never (a line that names no role is skipped).
    Feeds:   domain_status (its "role_summary")."""
    me = str(dc or "").split(".")[0].upper()
    held, elsewhere = [], []
    for line in lines or []:
        role, sep, owner = str(line).partition(" owner:")
        if not sep or not role.strip():
            continue
        name, who = ROLE_NAMES.get(role.strip(), role.strip()), _owner(owner)
        if who.split(".")[0].upper() == me:
            held.append(name)
        else:
            elsewhere.append({"role": name, "dc": who})
    if not held and not elsewhere:
        return {"text": "", "held": [], "elsewhere": []}
    five = sum(1 for r in held if r in list(ROLE_NAMES.values())[:5])
    if not elsewhere:
        extra = len(held) - five
        text = "This controller holds all five roles" if five == 5 else "This controller holds every role reported"
        text += f" (and the {extra} DNS zone masters)." if five == 5 and extra else "."
    else:
        text = ("This controller holds " + (", ".join(held) or "none of the roles") + "; "
                + "; ".join(f"{e['dc']} holds the {e['role']}" for e in elsewhere) + ".")
    return {"text": text, "held": held, "elsewhere": elsewhere}
