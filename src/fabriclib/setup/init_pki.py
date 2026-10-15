import json
import os
import shutil
import subprocess

import yaml

from fabriclib.common.console import info, ok
from fabriclib.consent.allowed_to_change import allowed_to_change
from fabriclib.consent.check_consent import check_consent
from fabriclib.consent.plan_trust import plan_trust
from fabriclib.pki.common.cert_dates import cert_dates
from fabriclib.pki.common.ca_path_len import ca_path_len
from fabriclib.pki.publish_ca_certs import publish_ca_certs
from fabriclib.setup.errors import SetupError

LIFETIME_FILE = "ca-lifetime"        # in the config folder: the root lifetime chosen (2.1.5.6)


def _chown_tree(path, uid, gid):
    """Purpose: give a whole directory tree to one owner.
    Inputs:  path — root of the tree; uid, gid — ints.
    Returns: None; path and everything below it chowned (symlinks followed).
    Fails:   OSError from os.chown.
    Feeds:   run (Step-CA's data folder to the step user)."""
    for root, dirs, files in os.walk(path):
        for name in [root] + [os.path.join(root, n) for n in dirs + files]:
            os.chown(name, uid, gid)


def _configure_ca_json(ca_json, v):
    """Purpose: converge Step-CA's ca.json after `step ca init`: bring-your-own chain paths, DNS names,
             certificate lifetimes, an ACME provisioner with fabric's ACME template, and fabric's leaf template on
             the JWK provisioner (setup's service certificates name the CRL, manual 1.5.1.3).
    Inputs:  ca_json — path to ca.json; v — vars: byoc, hostname_stepca, domain, stepca_cert_max_lifetime_hours
             (default 131400h), stepca_cert_allow_subordinate_ca, cert_acme_lifetime_hours (default 1128h).
    Returns: True if ca.json changed (rewritten, tab-indented; restart Step-CA). The ACME provisioner's template issues
             for names under the domain only (2.1.5.8, acme.tpl). With byoc its crt is certs/intermediate_chain.crt (the
             intermediate followed by its parent CAs, so a nested site's certificates carry the whole chain).
             With stepca_cert_allow_subordinate_ca the JWK provisioner
             may issue the basicConstraints extension (2.5.29.19).
    Fails:   OSError/json.JSONDecodeError reading ca.json; KeyError without hostname_stepca or
             "authority" in ca.json.
    Feeds:   run (the first initialisation, and every later run so existing installs converge)."""
    with open(ca_json) as f:
        cfg = json.load(f)
    if v.get("byoc"):
        cfg["root"] = "/home/step/certs/root_ca.crt"
        cfg["crt"] = "/home/step/certs/intermediate_chain.crt"      # the intermediate + its parent CAs (nested site)
        cfg["key"] = "/home/step/secrets/intermediate_ca_key"
    cfg["dnsNames"] = [v["hostname_stepca"], "localhost", "127.0.0.1"]
    auth = cfg["authority"]
    auth.setdefault("claims", {})["maxTLSCertDuration"] = str(v.get("stepca_cert_max_lifetime_hours", "131400h"))
    provisioners = auth.setdefault("provisioners", [])
    if not any(p.get("type") == "ACME" for p in provisioners):
        provisioners.append({"type": "ACME", "name": "acme"})
    for p in provisioners:
        if p.get("type") == "JWK":
            # the service certificates (pki/mint_cert) name the CRL like every other leaf: leaf.tpl (1.5.1.3)
            p.setdefault("options", {}).setdefault("x509", {})["templateFile"] = "/home/step/templates/certs/leaf.tpl"
        if p.get("type") == "JWK" and v.get("stepca_cert_allow_subordinate_ca"):
            p.setdefault("options", {}).setdefault("x509", {})["allowedExtensions"] = ["2.5.29.19"]
        if p.get("type") == "ACME":
            life = str(v.get("cert_acme_lifetime_hours", "1128h"))
            p.setdefault("claims", {}).update({"defaultTLSCertDuration": life, "maxTLSCertDuration": life})
            # LAN machines get names under fabric's domain only, never an address (2.1.5.8): acme.tpl refuses the
            # rest (a self-hosted Step-CA enforces policies only for the whole authority)
            p.setdefault("options", {})["x509"] = {"templateFile": "/home/step/templates/certs/acme.tpl"}
            p.pop("policy", None)
    text = json.dumps(cfg, indent="\t")
    with open(ca_json) as f:
        if f.read() == text:
            return False
    with open(ca_json, "w") as f:
        f.write(text)
    return True


def _single_intermediate(path):
    """Purpose: keep only the intermediate certificate in intermediate_ca.crt, the layout `step ca init` makes:
             the step CLI's offline signing (mint_offline_cert, sign_csr) takes exactly one certificate as --ca.
             Earlier bring-your-own installs appended the root there.
    Inputs:  path — Step-CA's certs/intermediate_ca.crt.
    Returns: True if the file held more than one certificate and was rewritten with the first one.
    Fails:   OSError reading or writing the file.
    Feeds:   run (first initialisation with byoc, and every later run, so existing installs converge)."""
    with open(path) as f:
        text = f.read()
    end = "-----END CERTIFICATE-----"
    if text.count(end) <= 1:
        return False
    with open(path, "w") as f:
        f.write(text[:text.index(end) + len(end)] + "\n")
    return True


def _make_root(ctx, data, uid, gid):
    """Purpose: make this install's own root CA before `step ca init`, with the path length that decides how
             deeply sites may nest below it (manual 1.9.5.1): ca_nest_depth + 1. `step ca init` alone
             makes path length 1 (flat sites only).
    Inputs:  ctx — SetupContext: vars ca_name, ca_nest_depth (0..4, default 1), image_stepca, cert_root_ca_days;
             data — Step-CA's data folder (secrets/password written); uid, gid — the step user.
    Returns: (root certificate path, root key path) in <data>/root-new (as /home/step/... for the container);
             EC P-256, cert_root_ca_days long (manual 2.1.5.6; default ten years), subject
             "O=<ca_name>, CN=<ca_name> Root CA" like step's own.
    Fails:   SetupError when ca_nest_depth is not 0..4 or step refuses.
    Feeds:   run (own root only)."""
    depth = ctx.vars.get("ca_nest_depth", 1)
    if not str(depth).isdigit() or not 0 <= int(depth) <= 4:
        raise SetupError(f"ca_nest_depth must be 0..4 (got {depth!r})")
    name = ctx.vars["ca_name"]
    os.makedirs(os.path.join(data, "root-new"), mode=0o700, exist_ok=True)
    with open(os.path.join(data, "root-new", "root.tpl"), "w") as f:
        json.dump({"subject": {"commonName": f"{name} Root CA", "organization": [name]},
                   "issuer": {"commonName": f"{name} Root CA", "organization": [name]},
                   "keyUsage": ["certSign", "crlSign"],
                   "basicConstraints": {"isCA": True, "maxPathLen": int(depth) + 1}}, f)
    _chown_tree(data, uid, gid)
    res = subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", f"{data}:/home/step", "-u",
                          f"{uid}:{gid}",
                          "--entrypoint", "/usr/local/bin/step", ctx.vars["image_stepca"], "certificate", "create",
                          f"{name} Root CA", "/home/step/root-new/root_ca.crt", "/home/step/root-new/root_ca_key",
                          "--template", "/home/step/root-new/root.tpl", "--kty", "EC", "--curve", "P-256",
                          "--not-after", f"{int(ctx.vars.get('cert_root_ca_days', 3650)) * 24}h",
                          "--password-file", "/home/step/secrets/password"],
                         capture_output=True, text=True)
    if res.returncode != 0:
        raise SetupError(f"making the root CA failed: {(res.stderr or res.stdout)[-600:]}")
    return "/home/step/root-new/root_ca.crt", "/home/step/root-new/root_ca_key"


def _intermediate_for_root(ctx, data, uid, gid):
    """Purpose: re-issue the intermediate `step ca init` made, to live the root's lifetime less one year (manual
             2.1.5.6), so it never outlives the root and leaves a year to replace it.
    Inputs:  ctx — SetupContext: vars ca_name, cert_root_ca_days, image_stepca; data — Step-CA's data folder (the
             root
             and its key under certs/ and secrets/, the password in secrets/password); uid, gid — the step user.
    Returns: None; certs/intermediate_ca.crt and secrets/intermediate_ca_key replaced (EC P-256, the key encrypted
             with the CA password, as step's own).
    Fails:   SetupError when step refuses.
    Feeds:   run (own root only, before the CA first starts)."""
    hours = (int(ctx.vars.get("cert_root_ca_days", 3650)) - 365) * 24
    name = ctx.vars["ca_name"]
    res = subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", f"{data}:/home/step", "-u",
                          f"{uid}:{gid}", "--entrypoint", "/usr/local/bin/step", ctx.vars["image_stepca"],
                          "certificate", "create", f"{name} Intermediate CA", "/home/step/certs/intermediate_ca.crt",
                          "/home/step/secrets/intermediate_ca_key", "--profile", "intermediate-ca",
                          "--ca", "/home/step/certs/root_ca.crt", "--ca-key", "/home/step/secrets/root_ca_key",
                          "--ca-password-file", "/home/step/secrets/password",
                          "--password-file", "/home/step/secrets/password", "--kty", "EC", "--curve", "P-256",
                          "--not-after", f"{hours}h", "--force"], capture_output=True, text=True)
    if res.returncode != 0:
        raise SetupError(f"issuing the intermediate CA failed: {(res.stderr or res.stdout)[-600:]}")


def _check_root_lifetime(v, certs_dir, config_dir):
    """Purpose: refuse a changed CA lifetime on an existing CA (manual 2.1.5.6): it is fixed once the CA is made. A CA
             made before 0.6.3 never had its lifetime chosen by this setting (0.6.2 rendered a default of 1825 days and
             made every root for 3650): its own lifetime is adopted, once, before anything is refused.
    Inputs:  v — vars: cert_root_ca_days, byoc (a brought-in root's lifetime is its own: not checked); certs_dir —
             Step-CA's certs folder; config_dir — the install's config folder (LIFETIME_FILE: the lifetime chosen,
             written when the CA is made or adopted; fabric.yaml, rewritten when one is adopted).
    Returns: None; on adopting, v["cert_root_ca_days"] is the CA's own lifetime.
    Fails:   SetupError saying the root's actual lifetime and what to do, when cert_root_ca_days differs from the
             lifetime chosen by more than a day; OSError writing the files.
    Feeds:   run (an existing CA)."""
    if v.get("byoc"):
        return
    dates = cert_dates(os.path.join(certs_dir, "root_ca.crt"))
    if not dates:
        return
    actual = round((dates[1] - dates[0]).total_seconds() / 86400)
    wanted = int(v.get("cert_root_ca_days", 3650))
    record = os.path.join(config_dir, LIFETIME_FILE)
    if not os.path.exists(record):          # made before the lifetime was a choice: the CA's own is the setting
        if abs(actual - wanted) > 1:
            v["cert_root_ca_days"] = actual
            fabric_yaml = os.path.join(config_dir, "fabric.yaml")
            if os.path.exists(fabric_yaml):
                with open(fabric_yaml) as f:
                    saved = yaml.safe_load(f) or {}
                saved["cert_root_ca_days"] = actual
                with open(fabric_yaml, "w") as f:
                    yaml.safe_dump(saved, f, sort_keys=False)
            ok(f"the CA's lifetime: {actual} days, as this CA was made (cert_root_ca_days set to it)")
        with open(record, "w") as f:
            f.write(f"{actual}\n")
        return
    if abs(actual - wanted) > 1:
        raise SetupError(f"cert_root_ca_days is {wanted}, but this install's root CA was made for {actual} days: a "
                         "CA's lifetime cannot change once it exists. Set cert_root_ca_days back to "
                         f"{actual} (sudo fabricctl edit), or start a new CA with a reinstall (manual 3.2.4).")


def _publish_ca_certs(ctx, certs_dir):
    """Purpose: publish every CA format at /certs/ (ca.<domain>, <host_ip>; 1.5.1.6) and trust the CA on this
             host; done on every setup, since a reinstall keeps the CA but not /opt/nginx or the host trust entries.
    Inputs:  ctx — SetupContext: vars.domain_file, service user nginx (uid/gid), config_dir (the `trust` consent:
             without it the CA is published but not added to the host's trust store); certs_dir — Step-CA certs
             folder.
    Returns: True if anything changed (from publish_ca_certs).
    Fails:   CalledProcessError from openssl/update-ca-certificates and OSError inside publish_ca_certs;
             KeyError without domain_file.
    Feeds:   run."""
    trusted = allowed_to_change(ctx.config_dir, "trust", plan_trust(ctx.vars))
    return publish_ca_certs(certs_dir, ctx.path("nginx", "www", "certs"), *ctx.uid("nginx"),
                            trust_prefix=f"fabric-{ctx.vars['domain_file']}" if trusted else None)


def _public_certs_readable(certs_dir):
    """Purpose: make the public CA certificates world-readable: the web UI (mounted read-only at /certs)
             verifies client certificates against root_ca.crt/intermediate_ca.crt. `step ca init` creates the
             folder 0700; keys live in secrets/, never here.
    Inputs:  certs_dir — Step-CA certs folder.
    Returns: None; the folder 0755, every *.crt in it 0644.
    Fails:   OSError if the folder is missing or chmod fails.
    Feeds:   run."""
    os.chmod(certs_dir, 0o755)
    for name in os.listdir(certs_dir):
        if name.endswith(".crt"):
            os.chmod(os.path.join(certs_dir, name), 0o644)


def run(ctx):
    """Purpose: initialise Step-CA once (its own root, or a bring-your-own root + intermediate when byoc),
             configure ca.json, publish the CA certificates and trust them on the host.
    Inputs:  ctx — SetupContext: vars byoc, ca_crt_path, ica_crt_path, ica_key_path (default: the .crt path
             with .key), ica_parents_path (a nested site's parent CAs), ca_nest_depth (own root: how many levels
             sites may nest; default 1), image_stepca, ca_name, hostname_stepca, stepca_port (default 9000) and
             the ca.json settings; secrets.ca_password; service user step.
    Returns: None. First run: <deploy_base>/stepca/data with the CA (password file 0600, owned by step; an own
             root made with path length ca_nest_depth + 1 by _make_root; with byoc, certs/ca_parents.crt and
             certs/intermediate_chain.crt for the parent CAs) and
             ca.json configured, chain verified, published and trusted; intermediate_ca.crt holds the
             intermediate alone (also converged on later runs, restarting stepca). With byoc the brought-in intermediate
             key may be encrypted with ca_password (a federation site's is) or not; the root key `step ca
             init` generated is removed, since it does not belong to the brought-in root. With an existing ca.json only
             the
             permissions, publishing and trust are (re)done.
    Fails:   SetupError when byoc files are missing, `step ca init` fails, or an existing CA's lifetime differs
             from cert_root_ca_days (_check_root_lifetime); CalledProcessError when
             `openssl verify` rejects the intermediate or from publishing; ValidationError from ctx.secrets
             when the secrets are in a locked OpenBao (not converted to SetupError); KeyError for missing vars.
    Feeds:   setup step `pki`, run by run_setup via STEPS.
    Notes:   trusting the CA on the host needs the `trust` consent; without it a warning, and the CA is only
             published (manual 1.2.9)."""
    v = ctx.vars
    check_consent(ctx.config_dir, "trust", plan_trust(v))       # warns once when declined; _publish_ca_certs checks
    data = ctx.path("stepca", "data")
    ca_json = os.path.join(data, "config", "ca.json")
    uid, gid = ctx.uid("step")
    if os.path.exists(ca_json):
        _check_root_lifetime(v, os.path.join(data, "certs"), ctx.config_dir)
        if _configure_ca_json(ca_json, v):
            _chown_tree(os.path.join(data, "config"), uid, gid)
            ctx.restart_services.add("stepca")
            ok("Step-CA's configuration converged (lifetimes, ACME for names under the domain)")
        if _single_intermediate(os.path.join(data, "certs", "intermediate_ca.crt")):
            ctx.restart_services.add("stepca")
            ok("intermediate_ca.crt: the intermediate alone (the root it carried is in root_ca.crt)")
        _public_certs_readable(os.path.join(data, "certs"))
        published = _publish_ca_certs(ctx, os.path.join(data, "certs"))
        ok("Step-CA already initialised" + ("; CA certs re-published and trusted" if published else ""))
        return

    if v.get("byoc"):
        ica_key = v.get("ica_key_path") or os.path.splitext(v.get("ica_crt_path", ""))[0] + ".key"
        missing = [p for p in (v.get("ca_crt_path"), v.get("ica_crt_path"), ica_key) if not p or not os.path.exists(p)]
        if missing:
            raise SetupError(f"byoc: missing root/intermediate files: {', '.join(map(str, missing))}")

    os.makedirs(os.path.join(data, "secrets"), mode=0o750, exist_ok=True)
    pw = os.path.join(data, "secrets", "password")
    with open(pw, "w") as f:
        f.write(ctx.secrets["ca_password"])
    os.chmod(pw, 0o600)
    _chown_tree(data, uid, gid)

    own_root = []
    if not v.get("byoc"):
        root_crt, root_key = _make_root(ctx, data, uid, gid)
        with open(os.path.join(ctx.config_dir, LIFETIME_FILE), "w") as f:      # chosen now: fixed from here on
            f.write(f"{int(v.get('cert_root_ca_days', 3650))}\n")
        own_root = [f"--root={root_crt}", f"--key={root_key}", "--key-password-file=/home/step/secrets/password"]
    info("initialising Step-CA")
    res = subprocess.run(["docker", "run", "--rm", "-v", f"{data}:/home/step", "-e", "STEPPATH=/home/step",
                          "-u", f"{uid}:{gid}", "--entrypoint", "/usr/local/bin/step", v["image_stepca"],
                          "ca", "init", f"--name={v['ca_name']}",
                          f"--dns={v['hostname_stepca']},localhost,127.0.0.1",
                          f"--address=:{v.get('stepca_port', 9000)}", "--provisioner=admin",
                          "--password-file=/home/step/secrets/password",
                          "--provisioner-password-file=/home/step/secrets/password", *own_root],
                         capture_output=True, text=True)
    if res.returncode != 0 or not os.path.exists(ca_json):
        raise SetupError(f"step ca init failed: {(res.stderr or res.stdout)[-600:]}")
    if own_root:              # the root key goes where sign_site_ca and step's own layout expect it
        shutil.move(os.path.join(data, "root-new", "root_ca_key"), os.path.join(data, "secrets", "root_ca_key"))
        shutil.rmtree(os.path.join(data, "root-new"))
        _intermediate_for_root(ctx, data, uid, gid)

    certs = os.path.join(data, "certs")
    if v.get("byoc"):
        shutil.copy2(v["ca_crt_path"], os.path.join(certs, "root_ca.crt"))
        shutil.copy2(v["ica_crt_path"], os.path.join(certs, "intermediate_ca.crt"))
        _single_intermediate(os.path.join(certs, "intermediate_ca.crt"))
        parents = ""
        if v.get("ica_parents_path") and os.path.exists(v["ica_parents_path"]):
            with open(v["ica_parents_path"]) as f:
                parents = f.read().strip()
        with open(os.path.join(certs, "ca_parents.crt"), "w") as f:          # empty for a flat site
            f.write(parents + "\n" if parents else "")
        with open(os.path.join(certs, "intermediate_ca.crt")) as f, \
                open(os.path.join(certs, "intermediate_chain.crt"), "w") as out:
            out.write(f.read().strip() + "\n" + (parents + "\n" if parents else ""))
        shutil.copy2(ica_key, os.path.join(data, "secrets", "intermediate_ca_key"))
        os.chmod(os.path.join(data, "secrets", "intermediate_ca_key"), 0o600)
        # `step ca init` made a root of its own: its key signs nothing that chains to the brought-in root
        os.remove(os.path.join(data, "secrets", "root_ca_key"))

    _configure_ca_json(ca_json, v)
    _chown_tree(data, uid, gid)
    _public_certs_readable(certs)
    parents_file = os.path.join(certs, "ca_parents.crt")
    untrusted = ["-untrusted", parents_file] if os.path.exists(parents_file) and os.path.getsize(parents_file) else []
    subprocess.run(["openssl", "verify", "-CAfile", os.path.join(certs, "root_ca.crt"), *untrusted,
                    os.path.join(certs, "intermediate_ca.crt")], check=True, capture_output=True)
    _publish_ca_certs(ctx, certs)
    with open(os.path.join(certs, "root_ca.crt")) as f:
        depth = ca_path_len(f.read())
    nest = "no limit" if depth is None else max(depth - 1, 0)
    ok(f"Step-CA initialised ({'bring-your-own root' if v.get('byoc') else 'own root'}; the root lets sites nest "
       f"{nest} level(s) below a site), CA certs published and trusted")
