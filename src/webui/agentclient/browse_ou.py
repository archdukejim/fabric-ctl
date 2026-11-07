import urllib.parse

from webui.agentclient.connection import call_agent


def browse_ou(ou="", q="", whole=False, internal=False):
    """Purpose: The directory browser's read (manual 1.8.8.4): the tree opened to one OU, its contents or a search.
             Agent route: GET /v1/directory/tree/ou=<path>/q=<text>/w=<0|1>/i=<0|1> (domain:read).
    Inputs:  ou — the OU's path ("" for the domain); q — text to find; whole — bool, the whole domain; internal —
             bool, the grants' computed groups shown (1.8.8.3).
    Returns: {"ou", "levels", "contents", "found", "kinds"}.
    Fails:   the call_agent exceptions: ValidationError (400: no such OU, a bad search, the DC not running),
             AgentError, AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/tree_page (/directory/tree).
    """
    seg = lambda k, v: urllib.parse.quote(f"{k}={v}", safe="=")      # noqa: E731  one segment, its slashes encoded
    return call_agent("GET", "/v1/directory/tree/" + "/".join(
        (seg("ou", ou), seg("q", q), seg("w", "1" if whole else "0"), seg("i", "1" if internal else "0"))))
