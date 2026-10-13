def get_dotted(data, dotted, default):
    """Purpose: read a dotted key ("security.firewall") from nested dicts.
    Inputs:  data — dict; dotted — key path; default — value when any part is missing or not a dict.
    Returns: the value found, or default.
    Fails:   never.
    Feeds:   setup/choose_plan, setup/apply_plan_defaults."""
    node = data
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def set_dotted(data, dotted, value):
    """Purpose: write a dotted key into nested dicts, creating intermediate dicts.
    Inputs:  data — dict (modified); dotted — key path; value — value to store.
    Returns: None.
    Fails:   TypeError/AttributeError if an intermediate key holds a non-dict value.
    Feeds:   setup/apply_plan_defaults."""
    parts = dotted.split(".")
    node = data
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value
