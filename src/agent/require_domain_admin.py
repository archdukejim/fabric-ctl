from fabriclib.backup.is_domain_admin import is_domain_admin
from fabriclib.common.errors import ValidationError

ONLY = "only the domain's Domain Admins may use backups (manual 1.3.7.12)"


def require_domain_admin(v, caller, check=is_domain_admin):
    """Purpose: the Domain Admins check every backup route makes first (manual 1.3.7.12), so a refusal changes
             nothing and reads nothing.
    Inputs:  v — rendered vars; caller — the token's user (None: a root peer); check — is_domain_admin (tests).
    Returns: None.
    Fails:   ValidationError: ONLY for anyone else; the DC's own word when it does not answer.
    Feeds:   agent/get_backup, agent/post_backup."""
    if not check(v, caller):
        raise ValidationError(ONLY)
