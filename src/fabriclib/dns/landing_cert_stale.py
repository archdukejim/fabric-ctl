import os

from fabriclib.dns.common.landing_names import landing_names
from fabriclib.pki.common.cert_names import cert_names


def landing_cert_stale(base, final_vars):
    """Purpose: whether the landing page's certificate still holds exactly the landing page's names (decision 2.1.4.8,
             manual 1.4.2.6); DNS' Apply does not issue it again (2.1.8.24), so it says what a full apply would change
             (decision 2.1.8.29).
    Inputs:  base — the deploy base (deploy_paths()["base"]); final_vars — the rendered settings (hostname_landing names
             the certificate's folder; landing_names reads the zone).
    Returns: None when the names are current or there is no certificate yet (setup issues the first one); else
             {"missing": [names the page answers at that the certificate lacks], "extra": [names it still holds]}.
    Fails:   never (an unreadable certificate counts as none).
    Feeds:   dns/apply_dns (its result, said on DNS' Review)."""
    folder = os.path.join(base, "nginx", "certs", str(final_vars.get("hostname_landing") or ""))
    have = cert_names(os.path.join(folder, "fullchain.pem"))
    want = set(landing_names(final_vars))
    if have is None or have == want:
        return None
    return {"missing": sorted(want - have), "extra": sorted(have - want)}
