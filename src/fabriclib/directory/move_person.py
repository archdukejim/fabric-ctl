from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.common.privileged_groups import privileged_groups
from fabriclib.directory.run_op import run_op
from fabriclib.federation.change_site_role import NAME_RE
from fabriclib.secrets.load_secrets import load_secrets


def move_person(v, actor, uid, target, source="cli", secrets=None, container="samba"):
    """Purpose: move a person's account to another site's OU=people (2.1.9.24, manual 1.6.3.18.8, 4.6.1.5): how an
             account comes to live at the level of the roles it holds. Only from a site above both its current site
             and the target (refused from below, by the DC's operation and by AD's limits on this site's agent);
             never below a site where it holds a role.
    Inputs:  v — fabric vars (site_name, fabric_groups' keys); actor — str, for the audit; uid — the user name;
             target — the site's name; source — audit source; secrets — fabric's secrets (default: load_secrets());
             container — the DC's container.
    Returns: {"uid", "from", "to", "moved"}.
    Fails:   ValidationError "user name and site: …" for a malformed name; the DC's refusals word for word ("no person
             …", "only a site above both may move …", "<uid> holds a role at …"); "the directory refused the change
             …" (AD); load_secrets' errors.
    Feeds:   directory/run_people_command (`fabricctl people move <uid> --site <site>`).
    Notes:   audited as PERSON_MOVE when it moved someone."""
    for name in (uid, target):
        if not NAME_RE.match(name or ""):
            raise ValidationError(f"user name and site: letters, digits, . _ - (got {name!r})")
    done = run_op(v, secrets if secrets is not None else load_secrets(), "move_person",
                  {"uid": uid, "target": target, "privileged": privileged_groups(v)}, container)
    if done.get("moved"):
        write_audit(actor, "PERSON_MOVE", f"user={uid} from={done.get('from')} to={done.get('to')}", source)
    return done
