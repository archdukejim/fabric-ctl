"""Write tests/setup/vars-0.7.1.yaml: the settings file a 0.7.1 install keeps (/opt/fabric/config/vars.yaml), made by
0.7.1's own code (its render_vars over its templates/vars.yaml.j2), from the answers a 0.7.1 setup saves for an
install with two zones, records, two TSIG keys with their rights and the optional parts (the move test's, 2.1.1.60).

    git worktree add /tmp/fabric-071 v0.7.1      (or: mkdir /tmp/fabric-071 && git archive v0.7.1 | tar -x -C it)
    python3 tests/setup/make_vars_071.py /tmp/fabric-071 tests/setup/vars-0.7.1.yaml

The images 0.7.1 pinned are its own lock's; its memory plan is for the host_ram_capacity below.
"""
import os
import sys

import yaml

tree, out = sys.argv[1], sys.argv[2]
sys.path[0:0] = [os.path.join(tree, "src")]
from fabriclib.common.jinja_env import jinja_env  # noqa: E402  (0.7.1's)
from fabriclib.deploy.render_vars import render_vars  # noqa: E402
from fabriclib.dns.normalize_tsig_keys import normalize_tsig_keys  # noqa: E402

# what 0.7.1's setup saves as fabric.yaml (its finish_vars): the answers, the DC's name it suggested, the log-on
# policy of a fresh install, and the first admin under 0.7.1's default name
answers = dict(
    deploy_base_dir="/opt", domain="move.home.arpa", hostname="fabric-sbx", host_ip="10.77.0.10",
    lan_cidr="10.77.0.0/24", lan_gateway="10.77.0.1", friendly_name="Fabric move test", ad_domain="ad.move.home.arpa",
    ad_password_policy={"minimum_length": 14, "complexity": True, "history": 24, "minimum_age_days": 0,
                        "maximum_age_days": 0, "lockout_threshold": 10, "lockout_minutes": 15,
                        "lockout_window_minutes": 15},
    install_keycloak=True, install_webui=True, install_fluentbit=True, dns_filter="bind",
    dc_name="dc-fabric-sbx", webui_admin_user="fabric-admin", webui_admin_email="admin@move.home.arpa",
    logon_policies={"machines": {"console": ["fabric-sbx-machine-admins"], "remote": ["fabric-sbx-machine-admins"]}},
    host_ram_capacity=8,
    tsig_keys=[{"name": "acme", "record_types": ["TXT"], "records": ["_acme-challenge.web"]},
               {"name": "ddns", "record_types": ["A", "AAAA"], "records": ["nas"]}],
    dns={"dynamic_zone_var": {"A": [{"name": "nas", "ip": "10.77.0.20"}],
                              "CNAME": [{"name": "files", "canonical": "nas"}]},
         "extra.home.arpa": {"zone_authority": True, "A": [{"name": "printer", "ip": "10.77.0.30"}]}},
)
answers["tsig_keys"], _ = normalize_tsig_keys(answers["tsig_keys"], answers["domain"], None)
# placeholders: the rendered settings hold no secret (they live in fabric-secrets.yml / OpenBao)
secrets = dict(ca_password="x", rndc_secret="eA==", keycloak_admin_user="admin", keycloak_admin_password="x",
               keycloak_db_password="x", webui_oidc_secret="x", tsig_secrets={"acme": "eA==", "ddns": "eA=="})
final, _ = render_vars(jinja_env(os.path.join(tree, "templates")), secrets, answers)
with open(out, "w") as f:
    f.write("# A 0.7.1 install's /opt/fabric/config/vars.yaml, made by 0.7.1's own code: tests/setup/make_vars_071.py\n")
    yaml.safe_dump(final, f, default_flow_style=False, allow_unicode=True)
