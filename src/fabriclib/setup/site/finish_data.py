import os

from fabriclib.common.sudo_owner import sudo_owner
from fabriclib.setup.errors import SetupError
from fabriclib.setup.site.certificate_fingerprint import certificate_fingerprint
from fabriclib.setup.site.finish_guides import finish_guides
from fabriclib.setup.site.mint_site_cert import mint_site_cert


def finish_data(ctx, addresses):
    """Purpose: what the finish page shows (manual 1.3.6.6), and the site's new certificate.
    Inputs:  ctx — SetupContext with the install's state: vars host_ip, domain, hostname_mgr; the root under
             nginx/www/certs; hostname_keycloak; addresses — the host's addresses.
    Returns: (finish dict, chain PEM or "", key PEM or ""). The dict: root_pem, root_fingerprint, certs_url,
             console_url, console_name, signin_name (where the console sends a browser to sign in), kit, trust, dns,
             and kept_temporary (what the page says) when no certificate could be had.
    Fails:   OSError when the published root cannot be read: setup says it finished, and that is setup's first failure
             to look at.
    Feeds:   setup/site/guided_site."""
    v = ctx.vars
    ip, name = v["host_ip"], v["hostname_mgr"]
    with open(ctx.path("nginx", "www", "certs", "root-ca.crt")) as f:
        root = f.read()
    _, home, _, _ = sudo_owner()
    certs_url = f"http://{ip}/certs/"
    trust, dns = finish_guides(ip, v["domain"], certs_url, name)
    data = {"root_pem": root, "root_fingerprint": certificate_fingerprint(root), "certs_url": certs_url,
            "console_url": f"https://{name}/", "console_name": name,
            "signin_name": v.get("hostname_keycloak", ""), "kit": os.path.join(home, "fabric-admin"),
            "trust": trust, "dns": dns}
    ordered = list(dict.fromkeys([ip, *addresses]))
    try:
        chain, key = mint_site_cert(ctx, ordered, name)
    except (SetupError, OSError) as e:
        data["kept_temporary"] = (f"This page stays on its temporary certificate: fabric's CA would not give it a new "
                                  f"one ({str(e)[:200]}). The rest of the finish holds.")
        chain, key = "", ""
    return data, chain, key
