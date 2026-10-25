from webui.views.constants import POLICY_FIELDS, POLICY_SECTIONS
from webui.views.render_page import render_page


def policies(ctx, view, domain=None, gpo=None, access=None, unavailable=""):
    """Purpose: Directory · Policies (manual 1.6.12.10): one page per kind of policy, all on Policies' one Apply: the
             password policy (the domain's default), Group Policy (the site's settings and controls, a search to set
             one) and the sudo rules.
    Inputs:  ctx — page context; view — "password", "gpo" or "sudo"; domain — domain_overview() (its policy) for
             password; gpo — gpo_overview() for gpo; access — {"groups", "sudo", "error"} for sudo (the host groups
             a rule may aim at); unavailable — why the policy could not be read.
    Returns: HTML str, in the navigation's Policies page.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/policies_page; devserver."""
    return render_page("policies", ctx=ctx, page="/directory/policies", view=view, sections=POLICY_SECTIONS,
                       domain=domain or {}, gpo=gpo or {}, access=access or {"groups": [], "sudo": [], "error": ""},
                       policy_fields=POLICY_FIELDS, unavailable=unavailable)
