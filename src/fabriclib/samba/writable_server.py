import socket
import time

from fabriclib.common.errors import ValidationError

PORT = 389              # the LDAP port the site's agent signs in on at another DC (directory_op: ldap://<server>)
TIMEOUT = 3             # seconds for one DC's reachability check
CACHE_SECONDS = 30      # how long one DC's answer is remembered by this process
_seen = {}              # server -> (epoch, answered: bool)


def _answers(server):
    """Purpose: whether a DC answers at all: a TCP connection to its LDAP port within TIMEOUT seconds.
    Inputs:  server — a DNS name or an IP address.
    Returns: bool.
    Fails:   never (every network error is "no").
    Feeds:   writable_server (tests replace it)."""
    try:
        with socket.create_connection((server, PORT), timeout=TIMEOUT):
            return True
    except OSError:
        return False


def _candidates(v):
    """Purpose: the writable DCs a read-only DC's site knows, in the order to try (2.1.6.57): `ad_writable_servers`,
             else `ad_join_server`, trimmed, without repeats.
    Inputs:  v — fabric vars.
    Returns: list of str (possibly empty).
    Fails:   never.
    Feeds:   writable_server."""
    listed = v.get("ad_writable_servers") or []
    if isinstance(listed, str):
        listed = [listed]
    out = []
    for s in list(listed) or [v.get("ad_join_server")]:
        s = str(s or "").strip()
        if s and s not in out:
            out.append(s)
    return out


def writable_server(v, to, now=None):
    """Purpose: the one choice of the DC a write to the domain goes to (decisions 2.1.6.52, 2.1.6.57, 2.1.10.23): this
             site's own, or at a site whose DC is read-only the first of its writable DCs that answers, tried in the
             order `ad_writable_servers` lists them (empty: `ad_join_server`), since a read-only DC takes no writes.
             A DC's answer is remembered for CACHE_SECONDS by this process, so a run of many writes asks once.
    Inputs:  v — fabric vars (ad_dc_type, ad_writable_servers, ad_join_server); to — what the write is, ending the
             refusal's sentence ("make the host's account at"); now — epoch seconds (tests), default time.time().
    Returns: None (this site's DC) or the writable DC's name or address (str, trimmed).
    Fails:   ValidationError, before anything is written: a read-only DC with no writable DC known; none of them
             answering (each DC tried named, with why).
    Feeds:   directory/run_op, ipam/common/edit_options, ipam/options/move_options_to_plan, samba/sync_rodc_cache,
             setup/common/host_identity, undo/remove_host_account, federation/change_dc_type."""
    if v.get("ad_dc_type") != "rodc":
        return None
    servers = _candidates(v)
    if not servers:
        raise ValidationError("this site's domain controller is read-only and no writable domain controller is known "
                              f"(ad_writable_servers, ad_join_server) to {to}")
    now = time.time() if now is None else now
    tried = []
    for server in servers:
        seen = _seen.get(server)
        if seen is None or now - seen[0] > CACHE_SECONDS:
            seen = (now, bool(_answers(server)))
            _seen[server] = seen
        if seen[1]:
            return server
        tried.append(f"{server}: did not answer")
    raise ValidationError("this site's domain controller is read-only and none of its writable domain controllers "
                          f"answers ({'; '.join(tried)}) to {to}; nothing was changed: try again when the link to one "
                          "of them is up, or list another in ad_writable_servers")
