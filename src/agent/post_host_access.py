from agent.read_strings import read_strings
from agent.read_text import read_text
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.directory.add_sudo_rule import add_sudo_rule
from fabriclib.directory.create_host_group import create_host_group
from fabriclib.directory.remove_host_group import remove_host_group
from fabriclib.directory.remove_sudo_rule import remove_sudo_rule
from fabriclib.directory.set_host_group_member import set_host_group_member


def post_host_access(route, actor, data, caller=None):
    """Purpose: host groups and sudo rules (manual 1.6.11.7): POST /v1/host-groups/... and /v1/sudo/... (fabriclib
             directory, as the site's agent account; changes in the directory at once, nothing to apply).
    Inputs:  route — ["host-groups"] (body: name), ["host-groups", <name>, "delete"], ["host-groups", <name>,
             "members"] (body: action add|remove, machine), ["sudo"] (body: name, users, commands and run_as as lists
             of text, hosts: a host group or ALL), ["sudo", <name>, "delete"]; actor — str; data — the JSON body; caller
             — the token's user (a machine's
             groups: fabric-agent's check, a grant's machines groups), or None for a root peer.
    Returns: host-groups: {"name"}; members: {"group", "machine", "member", "changed", "rules"}; sudo: {"name",
             "hosts"}; sudo/<name>/delete: {"name"}.
    Fails:   ValidationError("unknown operation") for another route, "action: add or remove", "<field> must be a list
             of text", or from fabriclib (-> 400).
    Feeds:   agent/post_route.py (POST host-groups/..., sudo/...)."""
    v = load_vars()
    if route == ["host-groups"]:
        return create_host_group(v, actor, read_text(data, "name"), source="web")
    if len(route) == 3 and route[0] == "host-groups" and route[2] == "delete":
        return remove_host_group(v, actor, route[1], source="web")
    if len(route) == 3 and route[0] == "host-groups" and route[2] == "members":
        action = data.get("action")
        if action not in ("add", "remove"):
            raise ValidationError("action: add or remove")
        return set_host_group_member(v, actor, route[1], read_text(data, "machine"), action == "add", source="web",
                                     caller=caller)
    if route == ["sudo"]:
        return add_sudo_rule(v, actor, read_text(data, "name"), read_strings(data, "users"),
                             read_strings(data, "commands"), read_strings(data, "run_as"),
                             read_text(data, "hosts") or None, source="web")
    if len(route) == 3 and route[0] == "sudo" and route[2] == "delete":
        return remove_sudo_rule(v, actor, route[1], source="web")
    raise ValidationError("unknown operation")
