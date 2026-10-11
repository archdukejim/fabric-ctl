from fabriclib.common.console import NC, YELLOW
from fabriclib.menu.constants import IMMUTABLE_KEYS


def permanent_mark(key):
    """Purpose: the label setup puts after a question whose answer cannot be changed after the install (2.1.2.20,
             manual 1.3.2.2): a yellow "⚠ Permanent". Which questions carry it is decided in one place, the vars
             editor's IMMUTABLE_KEYS, so the label and the editor's refusal cannot disagree.
    Inputs:  key — str, the setting the question sets (domain, ad_domain, dc_name, friendly_name, cert_root_ca_days, …).
    Returns: str: " ⚠ Permanent" (yellow on a terminal; the same words uncoloured with NO_COLOR or without a terminal)
             for an immutable setting; "" for one that can change.
    Fails:   never.
    Feeds:   setup/collect_vars (_ask), setup/ask_ad_domain, setup/ask_dc_name, setup/choose_plan (Advanced)."""
    return f" {YELLOW}⚠ Permanent{NC}" if key in IMMUTABLE_KEYS else ""
