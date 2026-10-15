# the Security extension and its editor: what Windows lists for a GptTmpl.inf
EXTENSIONS = "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"
BUILTIN_ADMINISTRATORS = "S-1-5-32-544"        # each machine's own local Administrators


def logon_rights_policy(sids, local_admins=(), remote=None):
    """Purpose: who may log on to a site's machines (2.1.6.14, manual 1.6.3.10, 1.6.11.4), and who is a local
             administrator on its Windows machines (2.1.9.13): the GptTmpl.inf granting interactive log-on (at the
             keyboard) to `sids` and remote interactive log-on (RDP; SSH through SSSD) to `remote`, and putting each of
             local_admins in every machine's own Administrators group (Restricted Groups "member of": added, never
             replacing who else is there), written as Windows writes it (UTF-16 with its byte-order mark, CRLF);
             Windows applies it, and Linux members the log-on part through SSSD's GPO access control (Q16).
    Inputs:  sids — list of SID str allowed at the keyboard (the groups granted, fabric-break-glass and each machine's
             local Administrators), in a stable order; local_admins — SID str of the groups made local
             Administrators (the site's and its parents' windows-admins); remote — list of SID str allowed
             remotely (None: the same as sids).
    Returns: bytes.
    Fails:   ValueError for an empty list (nobody could log on).
    Feeds:   ensure_logon_policies (a site's log-on GPOs)."""
    remote = sids if remote is None else remote
    if not sids or not remote:
        raise ValueError("a log-on policy needs at least one SID for each right")
    who, far = ",".join(f"*{s}" for s in sids), ",".join(f"*{s}" for s in remote)
    text = ("[Unicode]\r\nUnicode=yes\r\n[Version]\r\nsignature=\"$CHICAGO$\"\r\nRevision=1\r\n[Privilege Rights]\r\n"
            f"SeInteractiveLogonRight = {who}\r\nSeRemoteInteractiveLogonRight = {far}\r\n")
    if local_admins:
        text += "[Group Membership]\r\n" + "".join(f"*{s}__Memberof = *{BUILTIN_ADMINISTRATORS}\r\n"
                                                    for s in local_admins)
    return b"\xff\xfe" + text.encode("utf-16-le")      # little-endian with its mark, whatever the CPU
