import os


def fluentbit_pending(v):
    """Purpose: whether Fluent Bit must wait for fabric's PKI: on a fresh install setup's deploy step runs before its
             PKI step, so fabric's root CA, which verifies any destination without a ca_file of its own, is not made
             yet (manual 1.15.1.1; note 2.3.1.25.4). Setup's start step, after the PKI step, deploys it then.
    Inputs:  v — the rendered vars: install_fluentbit, deploy_base_dir, log_forwarding.
    Returns: True when Fluent Bit is on, a destination needs fabric's root CA, and Step-CA has not been initialised
             (no ca.json, no root CA); False otherwise, including an initialised CA whose root is missing, which
             deploy_fluentbit refuses.
    Fails:   never.
    Feeds:   deploy/deploy_optional_parts."""
    if not v.get("install_fluentbit"):
        return False
    lf = v.get("log_forwarding") or {}
    if all((lf.get(name) or {}).get("ca_file") for name in ("syslog", "elastic")):
        return False
    data = os.path.join(v["deploy_base_dir"], "stepca", "data")
    return not os.path.exists(os.path.join(data, "config", "ca.json")) \
        and not os.path.exists(os.path.join(data, "certs", "root_ca.crt"))
