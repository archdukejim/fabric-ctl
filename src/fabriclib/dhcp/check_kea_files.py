import os

from fabriclib.dhcp.check_kea_config import check_kea_config
from fabriclib.dhcp.common.kea_image import kea_image


def check_kea_files(v, secrets, jinja_env):
    """Purpose: render Kea's two configuration files and have Kea check each one that changed (check_kea_config),
             before anything of the apply is installed: a refusal then changes nothing. Checked only in deploy_kea,
             it came after BIND's files were installed, so a refused Kea file left BIND's new zone list in place and
             never reconfigured, and the next apply saw no change to reconfigure for (2.3.10.11.16).
    Inputs:  v — the rendered vars (deploy_base_dir, the normalized `dhcp`, image_kea); secrets — fabric's secrets
             (kea_ddns_secret); jinja_env — the Jinja environment holding kea/*.j2.
    Returns: dict {file name: rendered text} for kea-dhcp4.conf and kea-dhcp-ddns.conf.
    Fails:   ValidationError with Kea's own message when it refuses a changed file; jinja2 errors while rendering;
             subprocess.TimeoutExpired (60 s) from the check.
    Feeds:   deploy/apply_deployment (before installing), dhcp/deploy_kea (what it writes)."""
    ctx = {**v, "kea_ddns_secret": secrets.get("kea_ddns_secret", "")}
    texts = {name: jinja_env.get_template(f"kea/{name}.j2").render(**ctx)
             for name in ("kea-dhcp4.conf", "kea-dhcp-ddns.conf")}
    for name, text in texts.items():            # both checked before either is written
        dest = os.path.join(v["deploy_base_dir"], "kea", "config", name)
        if not os.path.exists(dest) or open(dest).read() != text:
            check_kea_config(kea_image(jinja_env, v), name, text)
    return texts
