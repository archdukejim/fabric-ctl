import yaml

from fabriclib.common.errors import ValidationError
from fabriclib.menu.constants import IMMUTABLE_KEYS, WARNED_KEYS
from fabriclib.settings.constants import CONSOLE, CONSOLE_ONLY, FORMAT, SECRET, SECRET_RE, UNKNOWN, WIZARD_KEYS


def parse_settings_file(text, known=()):
    """Purpose: read a settings file (manual 1.8.5.4): its wizard keys taken, every other key ignored and listed with
             why — *a secret*, *console only* or *not a setting*. Only the file's form is checked here; each value is
             checked by plan_settings, which refuses the whole file for one invalid value.
    Inputs:  text — the file's content (str); known — the names of this install's settings (vars.yaml's keys): a key
             among them, the permanent and network ones (IMMUTABLE_KEYS, WARNED_KEYS) or CONSOLE_ONLY is console-only.
    Returns: {"settings": {wizard key: value} in WIZARD_KEYS order, "ignored": [{"key", "reason"}] in the file's
             order}.
    Fails:   ValidationError, changing nothing: not YAML; not a map; no `fabric_settings: 1` (another version named);
             `settings` missing or not a map.
    Feeds:   agent/post_settings (POST /v1/settings/plan with a file), settings/run_settings_command
             (`fabricctl settings import`)."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ValidationError(f"not a settings file: it is not YAML ({str(e).splitlines()[0]})") from None
    if not isinstance(doc, dict):
        raise ValidationError("not a settings file: it holds no map of settings")
    if doc.get("fabric_settings") != FORMAT:
        found = doc.get("fabric_settings")
        raise ValidationError("not a settings file of this format: it needs `fabric_settings: 1`"
                              + (f" (it has {found!r})" if found is not None else ""))
    given = doc.get("settings")
    if not isinstance(given, dict):
        raise ValidationError("the settings file has no `settings:` map")
    console = set(known) | IMMUTABLE_KEYS | WARNED_KEYS | {k for k, _, _ in CONSOLE_ONLY}
    ignored = []
    for key in given:
        if key in WIZARD_KEYS:
            continue
        name = str(key)
        reason = SECRET if SECRET_RE.search(name) else CONSOLE if name in console else UNKNOWN
        ignored.append({"key": name, "reason": reason})
    return {"settings": {k: given[k] for k in WIZARD_KEYS if k in given}, "ignored": ignored}
