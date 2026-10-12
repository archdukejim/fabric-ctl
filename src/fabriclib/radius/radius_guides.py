from fabriclib.pki.common.ca_files import ca_files
from fabriclib.radius.windows_setup_script import windows_setup_script


def radius_guides(v, root_pem=None):
    """Purpose: What the FreeRADIUS tab's setup guides need, filled in for this install. Only public data.
    Inputs:  v — the vars dict (host_ip, hostname_radius, hostname_stepca, domain, radius_clients, radius_people,
             deploy_base_dir).
             root_pem — the fabric root CA as PEM; None reads <deploy_base>/stepca/data/certs/root_ca.crt.
    Returns: {"host_ip", "server_name", "certs_url", "domain", "clients" (names), "people" (group names), "windows":
             {"tls" | "ttls": {"filename", "script"}}}.
    Fails:   OSError if the root CA file cannot be read; binascii.Error from windows_setup_script on a malformed PEM.
    Feeds:   agent route GET /v1/radius/guides (fabric-agent, src/agent/, called by the web UI for
             src/webui/views); the web UI's dev preview (src/webui/devpreview); tests/render.py.
    """
    if root_pem is None:
        with open(ca_files(v)[0]) as f:
            root_pem = f.read()
    windows = {}
    for method in ("tls", "ttls"):
        filename, script = windows_setup_script(v, method, root_pem)
        windows[method] = {"filename": filename, "script": script}
    return {"host_ip": v.get("host_ip", ""), "server_name": v.get("hostname_radius", ""),
            "certs_url": f"http://{v.get('hostname_stepca', '')}/certs/", "domain": v.get("domain", ""),
            "clients": [c.get("name") for c in v.get("radius_clients") or []],
            "people": [m.get("group") for m in v.get("radius_people") or []],
            "windows": windows}
