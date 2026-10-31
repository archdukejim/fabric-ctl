import re

from fabriclib.access.check_access import check_access
from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.constants import site_group
from fabriclib.directory.people_password import people_password
from fabriclib.directory.run_op import run_op
from fabriclib.grants.sync_grants import sync_grants
from fabriclib.secrets.load_secrets import load_secrets

UID_RE = re.compile(r"^[a-z][a-z0-9._-]{1,31}$")
NAME_RE = re.compile(r"^[\w .,'-]{1,60}$")
MAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,}$")


def create_person(v, actor, uid, first, last, email, source="web", secrets=None, caller=None, container="samba"):
    """Purpose: Helpdesk `people:create` (manual 1.6.3): a new person in OU=people (the domain's, 2.1.6.64), with
             their POSIX identity from the DC's range, in this site's `site-<name>`, and a one-time password they
             change at their first sign-in (Keycloak asks; then TOTP enrolment).
    Inputs:  v — fabric vars (site_name, ad_password_policy, ldap_groups (the users gid), posix_home_base,
             posix_login_shell); actor — str, for the audit; uid — ^[a-z][a-z0-9._-]{1,31}$; first, last — letters and
             simple punctuation, 1-60; email — an address with a dotted domain; source — audit source; secrets —
             fabric's secrets (default: load_secrets()); caller — the signed-in person's user name (fabric-agent's
             check: a grant's people add whose where groups are all among the new person's, site-<site>, or a
             Directory Administrator), or None (root); container — the DC's container.
    Returns: the one-time password: shown once, stored nowhere.
    Fails:   ValidationError "user name: 2-32 characters …", "first and last name: …", "e-mail address looks wrong",
             "that name is already taken" (the user name or e-mail address, anywhere in the domain), the directory's
             refusals (run_op), check_access's, load_secrets' errors.
    Feeds:   agent route POST /v1/people (agent/post_route.py) -> webui agentclient.create_person -> People page.
    Notes:   audited as PERSON_CREATE. The grants are compiled at once (1.6.13.4): the new person is in site-<site>,
             so the grants on it reach them within this change, and a change held on them right after (a reset)
             is not refused for the timer's compile moving their groups (2.3.1.32)."""
    if not UID_RE.match(uid or ""):
        raise ValidationError("user name: 2-32 characters, a-z 0-9 . _ -, starting with a letter")
    if not NAME_RE.match(first or "") or not NAME_RE.match(last or ""):
        raise ValidationError("first and last name: letters and simple punctuation, at most 60")
    if not MAIL_RE.match(email or ""):
        raise ValidationError("e-mail address looks wrong")
    check_access(v, caller, "people:add", {"groups": [site_group(v["site_name"])]}, container)
    password = people_password(v)
    users_gid = next((int(g["gidNumber"]) for g in v.get("ldap_groups") or [] if g["name"] == "users"), 5000)
    run_op(v, secrets if secrets is not None else load_secrets(), "create_person",
           {"uid": uid, "first": first, "last": last, "email": email, "password": password, "gid": users_gid,
            "home_base": v.get("posix_home_base") or "/home", "shell": v.get("posix_login_shell") or "/bin/bash"},
           container)
    write_audit(actor, "PERSON_CREATE", f"user={uid}", source)
    sync_grants(v, actor, source, container, quiet=True)      # their site's group reaches grants at once (1.6.13.4)
    return password
