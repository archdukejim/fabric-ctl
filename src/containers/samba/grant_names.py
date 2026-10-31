"""The grants' names and vocabulary (manual 1.6.13.4, 1.6.13.5; 2.1.6.73, 2.1.6.77, 2.1.6.87): what a grant may hold,
the computed groups and GPOs fabric writes for them, the grants a fresh install ships and the templates."""
import re

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,39}$")
RESERVED = {"explain", "sync"}            # words of the CLI and the routes (/v1/domain/grants/explain/...)
KINDS = ("allow", "restrict")             # an allowing grant, or a restricting one (2.1.6.77)
PEOPLE_RIGHTS = ("edit", "reset", "unlock", "disable", "add")         # disable: and enable; add: and remove
MACHINE_RIGHTS = ("add", "move", "disable", "remove", "groups")       # groups: change a machine's groups
SIGNIN_RIGHTS = ("keyboard", "remote")    # SeInteractiveLogonRight; SeRemoteInteractiveLogonRight (RDP, SSH)
# the rights a set's GPO carries, and so the ones a restricting grant may narrow (1.6.13.4)
GPO_RIGHTS = ("keyboard", "remote", "local-admin")
SUDO_ALL = "ALL"
# every grant's fields, with what an empty one is
FIELDS = {"kind": "allow", "description": "", "who": [], "where": [], "people": [], "machines": [], "signin": [],
          "sudo": [], "local_admin": False}
FALLBACK_GPO = "fabric: access none"      # default deny (2.1.6.87)
BUILTIN_ADMINISTRATORS = "S-1-5-32-544"   # each machine's own Administrators
LOCAL_ADMIN = "local-admin"               # each machine's own break-glass account (2.1.7.15), by name
AUTHENTICATED_USERS = "S-1-5-11"
APPLY_GROUP_POLICY = "edacfd8f-ffb3-11d1-b41d-00a0c968f939"     # the Apply Group Policy extended right
SECURITY_EXTENSIONS = "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"
SECURITY_TEMPLATE = "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"
GROUP_MARK = "fabric: computed for the grants, written only by fabric (manual 1.6.13.4)"
STATE = "_compiled"                       # the store's record of the sets of machines (no grant name starts with _)

# what a fresh install ships (1.6.13.5), made once at the root's first convergence
SHIPPED = [
    {"name": "server-administrators", "description": "the servers' administrators (manual 1.6.13.5)",
     "who": ["server-admins"], "where": ["machines-servers"], "signin": ["keyboard", "remote"], "sudo": [SUDO_ALL],
     "local_admin": True},
    {"name": "desktop-administrators", "description": "the desktops' administrators (manual 1.6.13.5)",
     "who": ["desktop-admins"], "where": ["machines-desktops"], "signin": ["keyboard", "remote"],
     "sudo": [SUDO_ALL], "local_admin": True},
    {"name": "network-administrators", "description": "the network machines' administrators (manual 1.6.13.5)",
     "who": ["network-admins"], "where": ["machines-network"], "signin": ["keyboard", "remote"],
     "sudo": [SUDO_ALL], "local_admin": True},
    {"name": "desktops", "description": "every person signs in at the desktops (manual 1.6.13.5, 2.1.6.77)",
     "who": ["Domain Users"], "where": ["machines-desktops"], "signin": ["keyboard"]},
]
# the templates (1.6.13.5): rights only; who and where are given when a grant is made from one
TEMPLATES = {
    "helpdesk": {"description": "a help desk: people's details, passwords and lockouts (manual 1.6.13.5)",
                 "people": ["edit", "reset", "unlock"]},
    "limited-directory-administrator": {
        "description": "every category, on the groups it is given (manual 1.6.13.5, 2.1.6.68)",
        "people": list(PEOPLE_RIGHTS), "machines": list(MACHINE_RIGHTS), "signin": list(SIGNIN_RIGHTS),
        "sudo": [SUDO_ALL], "local_admin": True},
}


def who_group(name):
    """Purpose: a grant's computed group of its people (1.6.13.4).
    Inputs:  name — the grant's name.
    Returns: str "grant-<name>-who".
    Fails:   never.
    Feeds:   compile_grants, ensure_grant_sudo, explain_grants, show_grant."""
    return f"grant-{name}-who"


def where_group(name):
    """Purpose: a grant's computed group of the machines (and people) it reaches (1.6.13.4).
    Inputs:  name — the grant's name.
    Returns: str "grant-<name>-where".
    Fails:   never.
    Feeds:   compile_grants, ensure_grant_sudo, show_grant."""
    return f"grant-{name}-where"


def set_group(n, right=None):
    """Purpose: a set of machines' computed group (`access-<n>`, its computers), or one of its restricted rights'
             (`access-<n>-<right>`, the people left with that right there).
    Inputs:  n — int, the set's number; right — one of GPO_RIGHTS, or None.
    Returns: str.
    Fails:   never.
    Feeds:   compile_grants, show_grant."""
    return f"access-{n}" + (f"-{right}" if right else "")


def set_gpo(n):
    """Purpose: a set of machines' GPO (1.6.13.4).
    Inputs:  n — int.
    Returns: str "fabric: access <n>".
    Fails:   never.
    Feeds:   compile_grants."""
    return f"fabric: access {n}"


def gpo_rights(grant):
    """Purpose: the rights of a grant that its machines' GPO carries.
    Inputs:  grant — a stored grant (FIELDS' keys).
    Returns: list of GPO_RIGHTS items, in their order.
    Fails:   never.
    Feeds:   compile_grants, explain_grants, check_grant."""
    have = set(grant.get("signin") or []) | ({"local-admin"} if grant.get("local_admin") else set())
    return [r for r in GPO_RIGHTS if r in have]
