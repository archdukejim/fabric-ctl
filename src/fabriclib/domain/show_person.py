from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def show_person(v, uid, secrets=None, container="samba"):
    """Purpose: one person as the DC has them (manual 1.6.12.4): their groups and their details, AD's standard
             attributes (2.1.6.93).
    Inputs:  v — rendered vars; uid — the user name; secrets — fabric's secrets (default: load_secrets()); container —
             the DC's container.
    Returns: {"uid", "dn", "groups": [names], "person": {field: value}} (every field of person_fields.FIELDS; "" when
             not set; the manager by user name).
    Fails:   ValidationError from run_op (no such person, the DC not reachable) or load_secrets.
    Feeds:   agent/pending_thing (a person's version, 2.1.8.14).
    """
    return run_op(v, secrets if secrets is not None else load_secrets(), "get_person", {"uid": uid}, container)
