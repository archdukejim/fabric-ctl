from agent.read_tsig_edit import read_tsig_edit
from fabriclib.dns.edit_tsig_names import edit_tsig_names


def tsig_check(data, route, body):
    """Purpose: A TSIG key's Edit names checked when it is held, so a refusal is said on the key's page at once and
             nothing waits that DNS' Apply would refuse (manual 1.4.1.9.3; checked again when it runs at Apply).
    Inputs:  data — the vars now; route — the held change's segments after /v1/; body — its body.
    Returns: None (any other change: nothing to check here).
    Fails:   ValidationError from read_tsig_edit or edit_tsig_names, saying why (-> 400, nothing held).
    Feeds:   agent/post_pending (the pending store's check)."""
    if len(route) == 3 and route[0] == "tsig" and route[2] == "update":
        edit_tsig_names(data, route[1], read_tsig_edit(body))
