def vlan_reply(vlan, style="rfc3580"):
    """Purpose: the reply attributes that put a client on a VLAN, in the form its vendor takes (manual 1.11.1.2).
    Inputs:  vlan — int/str VLAN id, or None/0 for the port's default VLAN; style — the client profile's "vlan"
             ("rfc3580", what UniFi, Cisco and generic switches all take; anything unknown is treated the same).
    Returns: tuple of (attribute, ":=", value): Tunnel-Type VLAN, Tunnel-Medium-Type IEEE-802 and
             Tunnel-Private-Group-Id <vlan> (RFC 3580); () when there is no VLAN.
    Fails:   never.
    Feeds:   fabric_radius (_decide, _decide_person, _decide_peap); tests/freeradius/check_mab_test.py.
    """
    if not vlan:
        return ()
    return (("Tunnel-Type", ":=", "VLAN"), ("Tunnel-Medium-Type", ":=", "IEEE-802"),
            ("Tunnel-Private-Group-Id", ":=", str(vlan)))
