"""The host's coming move, kept in the domain for the machines fabric manages (decision 2.1.1.79, manual 1.4.1.8.7):
its record, which a Linux member reads as itself, and the GPO that gives Windows members both addresses."""
import ldb
from samba.dcerpc import preg
from samba.ndr import ndr_pack

from ensure_gpo import ensure_gpo
from find_gpo import find_gpo
from member_gpo_filter import member_gpo_filter
import paths

# the Registry and the Group Policy Preferences' Scheduled Tasks client-side extensions, with their editors' tools
EXTENSIONS = ("[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"
              "[{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]")
DNS_KEY, DNS_VALUE = "Software\\Policies\\Microsoft\\Windows NT\\DNSClient", "NameServer"
REG_SZ = 1
TASK_UID = "{6F1B2C9E-3D4A-4E57-9A10-7C2E5B8D1F31}"
TASK_NAME = "fabric secure channel"     # no colon: Windows refuses one in a task's name
TASK = "".join((
    '<?xml version="1.0" encoding="utf-8"?>\n',
    '<ScheduledTasks clsid="{{CC63F200-7309-4ba0-B154-A71CD118DBCC}}">',
    '<TaskV2 clsid="{{D8896631-B747-47a7-84A6-C155337F3BC8}}" name="{name}" image="2" ',
    'changed="2026-11-03 00:00:00" uid="{uid}">',
    '<Properties action="R" name="{name}" runAs="NT AUTHORITY\\System" logonType="S4U">',
    '<Task version="1.2"><RegistrationInfo><Author>fabric</Author><Description>After the host moved: Netlogon lost ',
    'its ',
    "domain controller (5719), so its secure channel is set up again (manual 1.4.1.8.7)</Description>",
    '</RegistrationInfo><Principals><Principal id="Author"><UserId>NT AUTHORITY\\System</UserId>',
    "<LogonType>S4U</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings>",
    "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>",
    "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
    "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate>",
    "<AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden>",
    "<ExecutionTimeLimit>PT5M</ExecutionTimeLimit><Priority>7</Priority></Settings><Triggers><EventTrigger>",
    '<Enabled>true</Enabled><Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;',
    '&lt;Select Path="System"&gt;*[System[Provider[@Name=\'NETLOGON\'] and EventID=5719]]&lt;/Select&gt;',
    "&lt;/Query&gt;&lt;/QueryList&gt;</Subscription></EventTrigger></Triggers>",
    '<Actions Context="Author"><Exec><Command>nltest.exe</Command><Arguments>/sc_reset:{domain}</Arguments></Exec>',
    "</Actions></Task></Properties></TaskV2></ScheduledTasks>\n"))


def gpo_name(site):
    """Purpose: the display name of the GPO that names the site's DNS servers to Windows members.
    Inputs:  site — str.
    Returns: str.
    Fails:   never.
    Feeds:   ensure_member_dns."""
    return f"fabric: {site} DNS servers"


def _record_dn(samdb, dc):
    """Purpose: where a DC's coming move is recorded, in fabric's state, which every authenticated account reads and
             only fabric's agents and the system write (2.1.6.79).
    Inputs:  samdb — SamDB; dc — the DC's name.
    Returns: str.
    Fails:   never.
    Feeds:   announced, announce, withdraw."""
    return f"CN={dc},CN=moves,{paths.fabric_dn(samdb)}"


def announced(samdb, dc):
    """Purpose: the move a DC has announced.
    Inputs:  samdb — SamDB; dc — the DC's name.
    Returns: (old address, new address), or None.
    Fails:   ldb.LdbError other than no such object.
    Feeds:   ensure_member_dns, move_tool."""
    try:
        found = samdb.search(base=_record_dn(samdb, dc), scope=ldb.SCOPE_BASE, attrs=["description"])
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return None
        raise
    old, new = str(found[0]["description"][0]).split()
    return old, new


def withdraw(samdb, dc):
    """Purpose: take a DC's announced move out of the domain.
    Inputs:  samdb — SamDB (as the system); dc — the DC's name.
    Returns: bool, whether there was one.
    Fails:   ldb.LdbError.
    Feeds:   announce, ensure_member_dns, move_tool."""
    if announced(samdb, dc) is None:
        return False
    samdb.delete(_record_dn(samdb, dc))
    return True


def announce(samdb, dc, old, new):
    """Purpose: record a DC's coming move, as `<old> <new>` in the record's description: what a Linux member searches
             by the address it uses now.
    Inputs:  samdb — SamDB (as the system); dc — the DC's name; old, new — addresses.
    Returns: bool, whether anything changed.
    Fails:   ldb.LdbError.
    Feeds:   move_tool."""
    if announced(samdb, dc) == (old, new):
        return False
    parent = f"CN=moves,{paths.fabric_dn(samdb)}"
    if not samdb.search(base=paths.fabric_dn(samdb), scope=ldb.SCOPE_ONELEVEL, expression="(cn=moves)", attrs=["dn"]):
        samdb.add({"dn": parent, "objectClass": "container"})
    withdraw(samdb, dc)
    samdb.add({"dn": _record_dn(samdb, dc), "objectClass": "container", "description": f"{old} {new}"})
    return True


def member_dns_files(addresses, domain):
    """Purpose: what the GPO holds: the DNS servers (DNS Client: DNS servers, space-separated, first preferred) and the
             Scheduled Task that runs `nltest /sc_reset` when Netlogon logs 5719 (1.4.1.8.7).
    Inputs:  addresses — list of str; domain — the AD domain's DNS name.
    Returns: {path under the GPO folder: bytes}.
    Fails:   never.
    Feeds:   ensure_member_dns."""
    f = preg.file()
    f.header.signature, f.header.version = "PReg", 1
    e = preg.entry()
    e.keyname, e.valuename, e.type, e.data = DNS_KEY, DNS_VALUE, REG_SZ, " ".join(addresses)
    f.num_entries = 1
    f.entries = [e]
    task = TASK.format(name=TASK_NAME, uid=TASK_UID, domain=domain)
    return {"Machine/Registry.pol": ndr_pack(f), "Machine/Preferences/ScheduledTasks/ScheduledTasks.xml": task.encode()}


def ensure_member_dns(samdb, lp, site, dc, host_ip):
    """Purpose: the record and the GPO as the host's address now says. A move arrived (the host no longer has the
             record's old address) takes the record out. While one is announced, the GPO names both addresses; after
             it, the host's alone, kept, since a Windows member's own settings may still name the old one. An install
             that never announced a move has no GPO.
    Inputs:  samdb — SamDB (as the system); lp — LoadParm (realm); site — str; dc — the DC's name; host_ip — str.
    Returns: list of str, what changed.
    Fails:   ldb.LdbError; OSError; NTSTATUSError from set_gpo_acl.
    Feeds:   converge (each convergence), move_tool."""
    done = []
    move = announced(samdb, dc)
    if move and move[0] != host_ip:
        withdraw(samdb, dc)
        done.append(f"the move to {move[1]} arrived: its announcement taken out")
        move = None
    name = gpo_name(site)
    if move is None and find_gpo(samdb, name) is None:
        return done
    addresses = list(move) if move else [host_ip]
    done += ensure_gpo(samdb, lp, name, str(samdb.domain_dn()), EXTENSIONS,
                       member_dns_files(addresses, lp.get("realm").lower()))
    return done + member_gpo_filter(samdb, lp, name)
