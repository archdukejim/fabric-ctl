"""The domain-wide roles' owners and the password policy in force (manual 4.6.5), read by fabric-agent's account in
the words `samba-tool fsmo show` and `samba-tool domain passwordsettings show` use, without either's process start of
about half a second on the test Pi (decision 2.1.8.35). tests/samba/domain.py compares them with samba-tool's."""
import ldb

NEVER = -0x8000000000000000
DAY, MINUTE = 86400 * 10_000_000, 60 * 10_000_000       # AD's intervals are in 100 ns, negative


def _roles(samdb):
    """Purpose: each role's owner.
    Inputs:  samdb — SamDB.
    Returns: list of str, as samba-tool prints them.
    Fails:   ldb.LdbError from the searches.
    Feeds:   roles_and_policy."""
    domain, forest = str(samdb.domain_dn()), str(samdb.get_root_basedn())
    places = [("SchemaMasterRole", str(samdb.get_schema_basedn())),
              ("InfrastructureMasterRole", f"CN=Infrastructure,{domain}"),
              ("RidAllocationMasterRole", f"CN=RID Manager$,CN=System,{domain}"), ("PdcEmulationMasterRole", domain),
              ("DomainNamingMasterRole", f"CN=Partitions,{samdb.get_config_basedn()}"),
              ("DomainDnsZonesMasterRole", f"CN=Infrastructure,DC=DomainDnsZones,{domain}"),
              ("ForestDnsZonesMasterRole", f"CN=Infrastructure,DC=ForestDnsZones,{forest}")]
    lines = []
    for name, base in places:
        try:
            res = samdb.search(base=base, scope=ldb.SCOPE_BASE, attrs=["fSMORoleOwner"])
        except ldb.LdbError as e:
            if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
                raise
            continue
        if res and "fSMORoleOwner" in res[0]:
            lines.append(f"{name} owner: {res[0]['fSMORoleOwner'][0].decode()}")
    return lines


def _days(value, unit):
    """Purpose: an AD interval in whole days or minutes.
    Inputs:  value — int, negative 100 ns, or NEVER; unit — DAY or MINUTE.
    Returns: int; 0 for never.
    Fails:   never.
    Feeds:   _policy."""
    return 0 if value == NEVER else int(abs(value) / unit)


def _policy(samdb):
    """Purpose: the domain's password settings.
    Inputs:  samdb — SamDB.
    Returns: list of str, as samba-tool prints them after its first line.
    Fails:   ldb.LdbError from the search.
    Feeds:   roles_and_policy."""
    res = samdb.search(base=samdb.domain_dn(), scope=ldb.SCOPE_BASE,
                       attrs=["pwdProperties", "pwdHistoryLength", "minPwdLength", "minPwdAge", "maxPwdAge",
                              "lockoutDuration", "lockoutThreshold", "lockOutObservationWindow"])[0]
    n = {a: int(v[0]) for a, v in ((a, res[a]) for a in ("pwdProperties", "pwdHistoryLength", "minPwdLength",
                                                         "minPwdAge", "maxPwdAge", "lockoutDuration",
                                                         "lockoutThreshold", "lockOutObservationWindow"))}
    return [f"Password complexity: {'on' if n['pwdProperties'] & 1 else 'off'}",
            f"Store plaintext passwords: {'on' if n['pwdProperties'] & 16 else 'off'}",
            f"Password history length: {n['pwdHistoryLength']}",
            f"Minimum password length: {n['minPwdLength']}",
            f"Minimum password age (days): {_days(n['minPwdAge'], DAY)}",
            f"Maximum password age (days): {_days(n['maxPwdAge'], DAY)}",
            f"Account lockout duration (mins): {_days(n['lockoutDuration'], MINUTE)}",
            f"Account lockout threshold (attempts): {n['lockoutThreshold']}",
            f"Reset account lockout after (mins): {_days(n['lockOutObservationWindow'], MINUTE)}"]


def roles_and_policy(samdb, lp, site):
    """Purpose: what `fabricctl domain status` and the console's Domain section show of the domain.
    Inputs:  samdb — SamDB; lp, site — as every op (not used).
    Returns: {"roles": [str], "policy": [str]}.
    Fails:   ldb.LdbError from the searches.
    Feeds:   directory_ops (roles_and_policy); fabriclib/samba/domain_status."""
    return {"roles": _roles(samdb), "policy": _policy(samdb)}
