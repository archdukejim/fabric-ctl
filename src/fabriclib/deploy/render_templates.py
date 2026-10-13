import os
import shutil

from fabriclib.common.errors import ValidationError
from fabriclib.dns.rfc2136_settings import rfc2136_settings

BIND_CONFIG = ("named.conf", "named.conf.acl", "named.conf.logs", "named.conf.options", "named.conf.tls",
               "named.conf.zones", "named.conf.keys", "rndc.key")
CERT_SCRIPTS = ("certs", "firefox-ubuntu", "chrome-ubuntu", "all-ubuntu", "python-ubuntu")


def _render(jinja_env, out, src, dest, context, **extra):
    """Purpose: render one template to <out>/<dest>.
    Inputs:  jinja_env; out — the render folder; src — template path under jinja/; dest — relative output path;
             context — the render context; extra — more variables for this template only.
    Returns: None.
    Fails:   ValidationError naming the template when it does not render; OSError writing.
    Feeds:   render_templates."""
    path = os.path.join(out, dest)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        text = jinja_env.get_template(src).render(**context, **extra)
    except Exception as e:                  # any template error: say which template
        raise ValidationError(f"rendering {src}: {e}")
    with open(path, "w") as f:
        f.write(text)


def render_templates(paths, jinja_env, context, final_vars, secrets, tsig_keys, units, reverse):
    """Purpose: render every configuration file of this install into the render folder (nothing is installed yet).
    Inputs:  paths — deploy_paths(); jinja_env; context — the full render context (settings, secrets, link vars,
             federation_links, reverse_zone_names); final_vars — rendered settings; secrets — for the RFC2136
             files; tsig_keys — normalized keys; units — service_units(); reverse — reverse_zones(final_vars).
    Returns: None. <render>/: nginx (config, web pages, certificate install scripts, static assets), each enabled
             unit's compose file and systemd wrapper, bind9 config and zones (forward and reverse),
             the web UI config and fabric-agent unit, the federation endpoint unit, OpenBao's config, Step-CA's
             certificate templates, an rfc2136.ini per TSIG key.
    Fails:   ValidationError when a template does not render; OSError copying the static files.
    Feeds:   apply_deployment."""
    out, jinja = paths["render"], paths["jinja"]

    def render(src, dest, **extra):
        _render(jinja_env, out, src, dest, context, **extra)

    for page in ("nginx/nginx.conf", "nginx/www/certs/index.html", "nginx/www/landing/index.html",
                 "nginx/www/manual/index.html", "nginx/www/certs/join-linux.sh"):
        render(f"{page}.j2", page)
    os.makedirs(os.path.join(out, "nginx/www/shared"), exist_ok=True)
    shutil.copy(os.path.join(jinja, "nginx/www/shared/style.css"), os.path.join(out, "nginx/www/shared/style.css"))
    for asset in ("marked.min.js", "mermaid.min.js"):
        shutil.copy(os.path.join(jinja, "nginx/www/manual", asset), os.path.join(out, "nginx/www/manual", asset))
    domain_file = context.get("domain_file", "example_com")
    for script in CERT_SCRIPTS:
        render(f"nginx/www/certs/install-{script}.sh.j2",
               f"nginx/www/certs/install-{script.replace('-ubuntu', '')}-{domain_file}.sh")

    for u in units:
        if u["enabled"]:
            render(f"{u['folder']}/docker-compose.yml.j2", f"{u['folder']}/docker-compose.yml")
            render("systemd/wrapper.service.j2", f"systemd/{u['service']}.service", item=u)

    for name in BIND_CONFIG:
        render(f"bind9/config/{name}.j2", f"bind9/config/{name}")
    for key, records in (final_vars.get("dns") or {}).items():
        zone = final_vars.get("domain") if key == "dynamic_zone_var" else key
        render("bind9/data/zone.j2", f"bind9/data/db.{zone}", zone_name=zone, zone_records=records)
    for zone, ptrs in reverse["zones"].items():
        render("bind9/data/reverse-zone.j2", f"bind9/data/db.{zone}", reverse_zone_name=zone, ptr_records=ptrs)

    if final_vars.get("install_webui"):
        render("webui/webui.json.j2", "webui/webui.json")
        render("systemd/fabric-agent.service.j2", "systemd/fabric-agent.service")
        render("systemd/fabric-scep-hook.service.j2", "systemd/fabric-scep-hook.service")    # manual 1.5.3.3
    if final_vars.get("federation_endpoint"):
        render("systemd/fabric-federation.service.j2", "systemd/fabric-federation.service")
    render("openbao/openbao.hcl.j2", "openbao/config/openbao.hcl")
    render("stepca/leaf.tpl.j2", "stepca/templates/certs/leaf.tpl")
    render("stepca/acme.tpl.j2", "stepca/templates/certs/acme.tpl")
    render("stepca/subca.tpl.j2", "stepca/templates/certs/subca.tpl")

    # RFC2136 client settings, one per TSIG key (the zone's own ACME key too)
    for key in tsig_keys:
        kdir = os.path.join(out, "rfc2136", key["name"])
        os.makedirs(kdir, exist_ok=True)
        with open(os.path.join(kdir, "rfc2136.ini"), "w") as f:
            f.write(rfc2136_settings(final_vars, key, secrets["tsig_secrets"].get(key["name"])))
