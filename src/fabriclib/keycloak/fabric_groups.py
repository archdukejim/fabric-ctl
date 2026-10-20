from fabriclib.directory.constants import DIRECTORY_ADMINS


def fabric_groups(v):
    """Purpose: The directory groups that carry a fabric role bundle (their members may only be reset by an
             admin).
    Inputs:  v — fabric vars: ldap_groups (list of {name, bundle?}).
    Returns: set of group names: the admin group (directory-admins, 2.1.6.81) plus every ldap_groups entry that names
             a bundle.
    Fails:   KeyError if an ldap_groups entry with a bundle has no name.
    Feeds:   reset_sign_in.
    """
    return {DIRECTORY_ADMINS} | {g["name"] for g in v.get("ldap_groups") or [] if g.get("bundle")}
