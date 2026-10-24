from fabriclib.common.errors import ValidationError
from fabriclib.federation.common.console_url import console_url
from fabriclib.federation.common.is_root_site import is_root_site
from fabriclib.federation.common.load_registry import load_registry
from fabriclib.federation.write_site_place import write_site_place


def keep_site_place(v, federation_file, secrets, container="samba"):
    """Purpose: this site keeps its own place in the federation on its record (decision 2.1.8.30, manual 1.8.6.12):
             its parent (the registry's upstream, none for the root) and its console's address, after every
             convergence; so a moved site, a renamed console or a lost record comes back as it is.
    Inputs:  v — rendered vars (site_name, dc_name, what write_site_place and console_url read); federation_file —
             the federation registry; secrets — fabric's secrets; container — this site's DC.
    Returns: list of str, what changed; a write the domain refused comes back as one line saying why (the
             selector's record waits for the next convergence; the domain's own convergence is not failed by it).
    Fails:   yaml/OSError from load_registry for a malformed registry.
    Feeds:   samba/converge_domain."""
    parent = "" if is_root_site(federation_file) else \
        str((load_registry(federation_file).get("upstream") or {}).get("site_name") or "")
    try:
        return write_site_place(v, secrets, v["site_name"], parent, console_url(v), container)
    except ValidationError as e:
        return [f"site selector: this site's place was not written ({e})"]
