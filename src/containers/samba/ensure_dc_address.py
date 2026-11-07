import ldb
from samba.dcerpc import dnsp
from samba.dnsserver import ARecord
from samba.ndr import ndr_pack, ndr_unpack

A = 1                                    # dnsp.DNS_TYPE_A
SERVER_TRUST, PARTIAL_SECRETS = 0x2000, 0x4000000     # userAccountControl: a DC, a read-only DC


def _addresses(node):
    """Purpose: the IPv4 addresses a DNS node's A records name.
    Inputs:  node — ldb.Message with dnsRecord.
    Returns: list of str.
    Fails:   never (a record that does not unpack raises from ndr_unpack).
    Feeds:   ensure_dc_address."""
    return [ndr_unpack(dnsp.DnssrvRpcRecord, bytes(v)).data for v in node.get("dnsRecord", [])
            if ndr_unpack(dnsp.DnssrvRpcRecord, bytes(v)).wType == A]


def _node(samdb, dn):
    """Purpose: one DNS node of the AD zones, or None when the DC never registered that name.
    Inputs:  samdb — SamDB; dn — the node's DN.
    Returns: ldb.Message (dnsRecord, dNSTombstoned) or None.
    Fails:   ldb.LdbError other than "no such object".
    Feeds:   ensure_dc_address."""
    try:
        return samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["dnsRecord", "dNSTombstoned"])[0]
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return None
        raise


def ensure_dc_address(samdb, lp, ip):
    """Purpose: this DC's own records in the AD domain's DNS at its address only (decision 2.1.1.74, known issue
             2.3.1.34): after the host moved, the DC's own update (samba_dnsupdate) asks the old address and fails,
             and nothing removed its records there, so members found the DC at an address that is gone. Its name,
             the domain itself (@), DomainDnsZones, ForestDnsZones and gc._msdcs get an A record at `ip` where it is
             missing, and lose every A record at an address the DC's own name held before (positive evidence of its
             old address) that no other DC's name holds.
    Inputs:  samdb — SamDB (as the system); lp — its loadparm (realm, netbios name); ip — the DC's address (HOST_IP,
             the LAN address its records name, 2.1.2.15).
    Returns: list of str, what was added or removed.
    Fails:   ldb.LdbError for a change AD refuses.
    Feeds:   converge."""
    base, realm = str(samdb.domain_dn()), lp.get("realm").lower()
    me = lp.get("netbios name").lower()
    zone = f"DC={realm},CN=MicrosoftDNS,DC=DomainDnsZones,{base}"
    forest = f"DC=_msdcs.{realm},CN=MicrosoftDNS,DC=ForestDnsZones,{base}"
    own = _node(samdb, f"DC={me},{zone}")
    old = {a for a in (_addresses(own) if own is not None else []) if a != ip}
    others = set()
    for r in samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, expression="(objectClass=computer)",
                          attrs=["sAMAccountName", "userAccountControl"]):
        name = str(r["sAMAccountName"][0]).rstrip("$").lower()
        if name != me and int(str(r.get("userAccountControl", [0])[0])) & (SERVER_TRUST | PARTIAL_SECRETS):
            node = _node(samdb, f"DC={name},{zone}")
            others |= set(_addresses(node)) if node is not None else set()
    stale = old - others
    done = []
    for label, dn in ((me, f"DC={me},{zone}"), ("@", f"DC=@,{zone}"),
                      ("DomainDnsZones", f"DC=DomainDnsZones,{zone}"), ("ForestDnsZones", f"DC=ForestDnsZones,{zone}"),
                      ("gc._msdcs", f"DC=gc,{forest}")):
        node = _node(samdb, dn)
        if node is None:                     # a name the DC never registered (no GC, a partition not held): left so
            continue
        values = list(node.get("dnsRecord", []))
        keep = [v for v in values if not (ndr_unpack(dnsp.DnssrvRpcRecord, bytes(v)).wType == A
                                          and ndr_unpack(dnsp.DnssrvRpcRecord, bytes(v)).data in stale)]
        removed = len(values) - len(keep)
        add = [] if ip in _addresses(node) or not (removed or label == me) else [ndr_pack(ARecord(ip))]
        if not removed and not add:
            continue
        msg = ldb.Message(node.dn)
        msg["dnsRecord"] = ldb.MessageElement([bytes(v) for v in keep] + add, ldb.FLAG_MOD_REPLACE, "dnsRecord")
        samdb.modify(msg)
        if add:
            done.append(f"DNS {label}: the DC's address {ip} added (2.1.1.74)")
        if removed:
            done.append(f"DNS {label}: the DC's old address {', '.join(sorted(stale))} removed (2.1.1.74)")
    return done
