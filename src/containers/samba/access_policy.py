from grant_names import BUILTIN_ADMINISTRATORS, LOCAL_ADMIN


def access_policy(keyboard, remote, local_admins):
    """Purpose: the security template of a set of machines' GPO, or of the fallback (manual 1.6.13.4, 2.1.6.87): sign-in
             at the keyboard (SeInteractiveLogonRight) to `keyboard` and remotely (SeRemoteInteractiveLogonRight: RDP;
             SSH through sssd) to `remote`, each followed by every machine's own Administrators and its `local-admin`
             (by name: a local account, so its SID is each machine's own), which no grant can take away; and each of
             `local_admins` put in the machine's Administrators (Restricted Groups "member of": added, never replacing
             who else is there). Written as Windows writes it: UTF-16 with its byte-order mark, CRLF. Windows applies
             it all; sssd the sign-in rights (it ignores a name it cannot read as a SID).
    Inputs:  keyboard, remote — lists of SID str (the grants' computed groups); local_admins — list of SID str.
    Returns: bytes.
    Fails:   never.
    Feeds:   compile_grants."""
    tail = [f"*{BUILTIN_ADMINISTRATORS}", LOCAL_ADMIN]
    at = ",".join([f"*{s}" for s in sorted(set(keyboard))] + tail)
    far = ",".join([f"*{s}" for s in sorted(set(remote))] + tail)
    text = ("[Unicode]\r\nUnicode=yes\r\n[Version]\r\nsignature=\"$CHICAGO$\"\r\nRevision=1\r\n[Privilege Rights]\r\n"
            f"SeInteractiveLogonRight = {at}\r\nSeRemoteInteractiveLogonRight = {far}\r\n")
    if local_admins:
        text += "[Group Membership]\r\n" + "".join(f"*{s}__Memberof = *{BUILTIN_ADMINISTRATORS}\r\n"
                                                    for s in sorted(set(local_admins)))
    return b"\xff\xfe" + text.encode("utf-16-le")      # little-endian with its mark, whatever the CPU
