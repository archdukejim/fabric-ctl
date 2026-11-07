"""The host's coming move, kept in the domain for the machines fabric manages (decision 2.1.1.79, manual 1.4.1.8.7):
its record, which a Linux member reads as itself, and the GPO whose scheduled task gives a Windows member both
addresses and sets its secure channel up again."""
from xml.sax.saxutils import escape

import ldb

from ensure_gpo import ensure_gpo
from find_gpo import find_gpo
from member_gpo_filter import member_gpo_filter
import paths

# the Group Policy Preferences' Scheduled Tasks client-side extension, with its editor's tool
EXTENSIONS = "[{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"
TASK_UID = "{6F1B2C9E-3D4A-4E57-9A10-7C2E5B8D1F31}"
TASK_NAME = "fabric secure channel"     # no colon: Windows refuses one in a task's name
# run 18 (2.3.1.44): real Windows Server 2025 ignored DNS Client's NameServer policy, and logged 5719 once, too early
# for a single nltest. So the task itself sets a fixed-address adapter's servers, and tries until the channel holds.
SCRIPT = ("$known = @({known}); $use = @({use}); "
          "Get-NetIPInterface -AddressFamily IPv4 -Dhcp Disabled -ConnectionState Connected | ForEach-Object {{ "
          "$i = $_.ifIndex; "
          "$now = @((Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4).ServerAddresses); "
          "if (@($now | Where-Object {{ $known -contains $_ }}).Count) {{ "
          "$rest = @($now | Where-Object {{ $known -notcontains $_ }}); "
          "Set-DnsClientServerAddress -InterfaceIndex $i -ServerAddresses ($use + $rest) }} }}; "
          "nltest /sc_verify:{domain} | Out-Null; "
          "if ($LASTEXITCODE -ne 0) {{ Clear-DnsClientCache; nltest /sc_reset:{domain} | Out-Null; "
          "exit $LASTEXITCODE }}")
REPEAT = ("<TimeTrigger><Enabled>true</Enabled><StartBoundary>2026-11-03T00:00:00</StartBoundary><Repetition>"
          "<Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></TimeTrigger>")
TASK = "".join((
    '<?xml version="1.0" encoding="utf-8"?>\n',
    '<ScheduledTasks clsid="{{CC63F200-7309-4ba0-B154-A71CD118DBCC}}">',
    '<TaskV2 clsid="{{D8896631-B747-47a7-84A6-C155337F3BC8}}" name="{name}" image="2" ',
    'changed="2026-11-03 00:00:00" uid="{uid}">',
    '<Properties action="R" name="{name}" runAs="NT AUTHORITY\\System" logonType="S4U">',
    '<Task version="1.2"><RegistrationInfo><Author>fabric</Author><Description>The host is moving or has moved: ',
    "this machine's DNS servers, and its secure channel set up again (manual 1.4.1.8.7)</Description>",
    '</RegistrationInfo><Principals><Principal id="Author"><UserId>NT AUTHORITY\\System</UserId>',
    "<LogonType>S4U</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings>",
    "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>",
    "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
    "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate>",
    "<AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden>",
    "<ExecutionTimeLimit>PT5M</ExecutionTimeLimit><Priority>7</Priority></Settings><Triggers>",
    "<RegistrationTrigger><Enabled>true</Enabled></RegistrationTrigger>{repeat}<EventTrigger>",
    '<Enabled>true</Enabled><Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;',
    '&lt;Select Path="System"&gt;*[System[Provider[@Name=\'NETLOGON\'] and EventID=5719]]&lt;/Select&gt;',
    "&lt;/Query&gt;&lt;/QueryList&gt;</Subscription></EventTrigger></Triggers>",
    '<Actions Context="Author"><Exec><Command>powershell.exe</Command><Arguments>{args}</Arguments></Exec>',
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


def note_previous(samdb, dc, old, new):
    """Purpose: remember an address the members may still name, once it is no longer announced (a move arrived, or was
             cancelled), so the task can take it out of a machine's DNS servers. Its description starts with a word, so
             a Linux member's search by address never finds it.
    Inputs:  samdb — SamDB (as the system); dc — the DC's name; old — the address to take out; new — the host's now.
    Returns: None.
    Fails:   ldb.LdbError.
    Feeds:   ensure_member_dns, move_tool."""
    dn = f"CN={dc}-previous,CN=moves,{paths.fabric_dn(samdb)}"
    try:
        samdb.delete(dn)
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
            raise
    samdb.add({"dn": dn, "objectClass": "container", "description": f"previous {old} {new}"})


def _previous(samdb, dc):
    """Purpose: the addresses note_previous kept.
    Inputs:  samdb — SamDB; dc — the DC's name.
    Returns: (old, new), or None.
    Fails:   ldb.LdbError other than no such object.
    Feeds:   ensure_member_dns."""
    try:
        found = samdb.search(base=f"CN={dc}-previous,CN=moves,{paths.fabric_dn(samdb)}", scope=ldb.SCOPE_BASE,
                             attrs=["description"])
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return None
        raise
    return tuple(str(found[0]["description"][0]).split()[1:])


def member_dns_files(use, known, domain, announced_now):
    """Purpose: what the GPO holds: the Scheduled Task that gives a fixed-address adapter naming a `known` address the
             servers `use`, and sets the secure channel up again when it does not hold (1.4.1.8.7). It runs when it is
             registered and on Netlogon's 5719, and every 5 minutes while a move is announced: 5719 is logged once, and
             may come before the DC's new address is in place.
    Inputs:  use — list of str, the servers, first preferred; known — list of str, fabric's addresses, past and present;
             domain — the AD domain's DNS name; announced_now — bool.
    Returns: {path under the GPO folder: bytes}.
    Fails:   never.
    Feeds:   ensure_member_dns."""
    script = SCRIPT.format(known=",".join(f"'{n}'" for n in known), use=",".join(f"'{n}'" for n in use), domain=domain)
    args = escape(f'-NoProfile -NonInteractive -Command "{script}"')
    task = TASK.format(name=TASK_NAME, uid=TASK_UID, repeat=REPEAT if announced_now else "", args=args)
    return {"Machine/Preferences/ScheduledTasks/ScheduledTasks.xml": task.encode()}


def ensure_member_dns(samdb, lp, site, dc, host_ip):
    """Purpose: the record and the GPO as the host's address now says. A move arrived (the host no longer has the
             record's old address) takes the record out. While one is announced, the GPO's task gives both addresses;
             after it, the host's alone, kept, since a machine that was off may yet have to take the old one out. An
             install that never announced a move has no GPO.
    Inputs:  samdb — SamDB (as the system); lp — LoadParm (realm); site — str; dc — the DC's name; host_ip — str.
    Returns: list of str, what changed.
    Fails:   ldb.LdbError; OSError; NTSTATUSError from set_gpo_acl.
    Feeds:   converge (each convergence), move_tool."""
    done = []
    move = announced(samdb, dc)
    if move and move[0] != host_ip:
        withdraw(samdb, dc)
        note_previous(samdb, dc, move[0], host_ip)
        done.append(f"the move to {move[1]} arrived: its announcement taken out")
        move = None
    name = gpo_name(site)
    if move is None and find_gpo(samdb, name) is None:
        return done
    kept = _previous(samdb, dc)
    if move:                # an announcement another replaced may be on a machine too
        use, known = list(move), sorted({*move, *((kept[0],) if kept else ())})
    else:
        if kept and kept[1] != host_ip:             # moved by hand since: the address it last knew is the old one now
            kept = (kept[1], host_ip)
            note_previous(samdb, dc, *kept)
        use, known = [host_ip], sorted({host_ip, *(kept or ())})
    done += ensure_gpo(samdb, lp, name, str(samdb.domain_dn()), EXTENSIONS,
                       member_dns_files(use, known, lp.get("realm").lower(), bool(move)))
    return done + member_gpo_filter(samdb, lp, name)
