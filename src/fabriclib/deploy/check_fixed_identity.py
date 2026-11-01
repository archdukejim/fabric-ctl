import os

from fabriclib.common.ensure_dir import ensure_dir
from fabriclib.common.errors import ValidationError
from fabriclib.federation.common.site_name_problem import site_name_problem
from fabriclib.federation.constants import BASE_DN_RE

MARKERS = (("site_name", ".site-name"), ("org_domain", ".org-domain"), ("ldap_base_dn", ".ldap-base-dn"))
HOSTNAME_MARKER = ".hostname"


def _hostname_problem(final_vars, config_dir):
    """Purpose: a host that runs a domain controller keeps its name except through break glass (decision 2.1.6.104,
             manual 1.6.11.14): its name is recorded on the first deploy and only `fabricctl admin rename-host`
             changes the record, so a name changed anywhere else (vars.yaml, the menu, setup run again) is refused
             before anything is rendered. A host without a DC is not held to it.
    Inputs:  final_vars — rendered settings (hostname, hostname_dc); config_dir — <fabric>/config (.hostname).
    Returns: str, the refusal (the recorded name, the DC, the break-glass command); "" when the name may be used.
    Fails:   OSError reading the record.
    Feeds:   check_fixed_identity."""
    marker = os.path.join(config_dir, HOSTNAME_MARKER)
    if not final_vars.get("hostname_dc") or not os.path.exists(marker):
        return ""
    recorded, name = open(marker).read().strip(), str(final_vars.get("hostname") or "")
    if not recorded or recorded == name:
        return ""
    dc = str(final_vars.get("hostname_dc")).split(".")[0]
    return (f"hostname is '{recorded}' on this host, which runs the domain controller {dc}: a domain controller's host "
            f"is renamed only through break glass, `sudo fabricctl admin rename-host {name} --reason \"<why>\"` "
            f"(manual 4.2.4.3); to apply anything else, set hostname: {recorded}")


def check_fixed_identity(final_vars, config_dir):
    """Purpose: the settings that name the directory stay what they were at install: site_name (this site's part),
             org_domain and ldap_base_dn (the organisation's), and the host's name where it runs a domain controller
             (changed only through break glass, 2.1.6.104). Recorded on the first deploy.
    Inputs:  final_vars — rendered settings; config_dir — <fabric>/config (holds .site-name, .org-domain,
             .ldap-base-dn, and .hostname on a DC's host).
    Returns: None; a missing marker is written with the current value.
    Fails:   ValidationError when site_name is not one host-name label or names an organisation OU, ldap_base_dn is
             not dc=… or o=… followed by dc=… parts, or a value differs from its marker; nothing is written then.
    Feeds:   apply_deployment (before anything is rendered or installed)."""
    org_ous = [ou.get("name") for ou in final_vars.get("ldap_organizational_units") or [] if not ou.get("parent")]
    problem = site_name_problem(final_vars.get("site_name", ""), org_ous)
    if problem:
        raise ValidationError(f"site_name: {problem}")
    if not BASE_DN_RE.match(str(final_vars.get("ldap_base_dn", ""))):
        raise ValidationError(f"ldap_base_dn '{final_vars.get('ldap_base_dn')}' is not dc=… or o=… followed by dc=… "
                              "parts")
    problem = _hostname_problem(final_vars, config_dir)
    if problem:
        raise ValidationError(problem)
    markers = MARKERS + (((("hostname", HOSTNAME_MARKER),) if final_vars.get("hostname_dc") else ()))
    for key, name in markers:
        marker = os.path.join(config_dir, name)
        if os.path.exists(marker):
            recorded = open(marker).read().strip()
            if recorded and recorded != final_vars.get(key):
                raise ValidationError(f"{key} is '{recorded}' on this install and cannot change "
                                      f"(asked: '{final_vars.get(key)}'); set {key}: {recorded}")
        else:
            ensure_dir(os.path.dirname(marker))
            with open(marker, "w") as f:
                f.write(str(final_vars.get(key, "")) + "\n")
