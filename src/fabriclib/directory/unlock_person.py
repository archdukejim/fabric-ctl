from fabriclib.common.write_audit import write_audit
from fabriclib.directory.common.person_guard import person_guard
from fabriclib.directory.run_op import run_op
from fabriclib.keycloak.clear_lockout import clear_lockout
from fabriclib.secrets.load_secrets import load_secrets


def unlock_person(v, actor, uid, privileged=False, source="web", secrets=None, own_site=False, container="samba"):
    """Purpose: `people:unlock` (manual 1.6.3.18, 2.1.9.21): a person locked out by too many wrong passwords can sign
             in again with the password they have — the directory account's lockout cleared and Keycloak's own copy
             of the lockout too; their password, TOTP and sessions stay (a forgotten password is a reset).
    Inputs:  v — fabric vars (site_name, fabric_groups', keycloak_admin's); actor — str, for the audit; uid — the
             user name; privileged — bool: root, or system:admin (a fabric-group member needs it); source — audit
             source; secrets — fabric's secrets (default: load_secrets()); own_site — bool, the caller is the site
             helpdesk (site:people:unlock only): this site's own people who hold no role; container — the DC's
             container.
    Returns: {"uid", "unlocked" (bool: false when the account was not locked)}.
    Fails:   ValidationError from person_guard (no such person; a fabric-group member without privileged; for
             own_site another site's person or one who holds a role) or run_op (AD refusing: outside this site's
             OU); "Keycloak refused: …"; load_secrets' errors.
    Feeds:   agent route POST /v1/people/<uid>/unlock (people:unlock, or site:people:unlock at this site);
             directory/run_people_command (`fabricctl people unlock`).
    Notes:   audited as PERSON_UNLOCK when it changed something."""
    secrets = secrets if secrets is not None else load_secrets()
    person_guard(v, secrets, uid, privileged, "unlock them", container=container, own_site=own_site)
    done = run_op(v, secrets, "unlock_person", {"uid": uid}, container)
    clear_lockout(v, secrets, uid)          # Keycloak's own brute-force lockout goes with it
    if done.get("unlocked"):
        write_audit(actor, "PERSON_UNLOCK", f"user={uid}", source)
    return done
