import copy
import re

from fabriclib.common.errors import ValidationError
from fabriclib.dns_filter.check_filter_settings import check_filter_settings
from fabriclib.samba.check_password_policy import DEFAULT_POLICY, check_password_policy
from fabriclib.setup.common.parse_log_target import parse_log_target
from fabriclib.system.common.parse_mem_mb import parse_mem_mb

MIN_RAM_GB = 4                      # 2.1.2.3: a Raspberry Pi with 4 GB is the smallest host
_WORD = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
_LOG_PARTS = {"syslog": ("host", "port", "tls", "message_key"), "elastic": ("url", "index", "user")}


def _flag(key, value):
    """Purpose: a true-or-false setting.
    Inputs:  key — its name; value — the value given.
    Returns: bool.
    Fails:   ValidationError for anything but true or false.
    Feeds:   check_wizard_value."""
    if not isinstance(value, bool):
        raise ValidationError(f"{key}: true or false, not {value!r}")
    return value


def _log_forwarding(value):
    """Purpose: where the logs go (manual 1.15.1): a syslog server and/or an Elasticsearch URL, checked as setup asks
             them (parse_log_target); what names something on the host (a CA file, names it resolves) is the console's.
    Inputs:  value — {} or null (nowhere), or {syslog: {host, port, tls, message_key}, elastic: {url, index, user},
             buffer_limit}.
    Returns: the value, normalised (port an int).
    Fails:   ValidationError naming the part: not a map; an unknown part or key; `ca_file` or `hosts` (console only);
             a host, port or URL setup refuses; a word that is not one; a buffer that is not a size.
    Feeds:   check_wizard_value."""
    if value in (None, ""):
        return {}
    if not isinstance(value, dict):
        raise ValidationError("log_forwarding: a map with syslog and/or elastic, or {} for none")
    out = {}
    for part, conf in value.items():
        if part == "hosts":
            raise ValidationError("log_forwarding.hosts names addresses for this host to resolve: console only (the "
                                  "vars editor, sudo fabricctl)")
        if part == "buffer_limit":
            parse_mem_mb(conf, "log_forwarding.buffer_limit")
            out[part] = conf
            continue
        if part not in _LOG_PARTS or not isinstance(conf, dict):
            raise ValidationError(f"log_forwarding.{part}: only syslog, elastic and buffer_limit, each syslog or "
                                  "elastic a map")
        if "ca_file" in conf:
            raise ValidationError(f"log_forwarding.{part}.ca_file names a file on this host: console only (the vars "
                                  "editor, sudo fabricctl)")
        unknown = sorted(set(conf) - set(_LOG_PARTS[part]))
        if unknown:
            raise ValidationError(f"log_forwarding.{part}: no {', '.join(map(str, unknown))} (only "
                                  f"{', '.join(_LOG_PARTS[part])})")
        conf = dict(conf)
        if part == "syslog":
            port = conf.get("port", 6514)
            if isinstance(port, bool) or not isinstance(port, int):
                raise ValidationError(f"log_forwarding.syslog.port: a number 1-65535, not {port!r}")
            try:
                parse_log_target(f"{conf.get('host') or ''}:{port}")
            except ValidationError as e:
                raise ValidationError(f"log_forwarding.syslog: {e}") from None
            conf["port"] = port
            if not isinstance(conf.get("tls", True), bool):
                raise ValidationError("log_forwarding.syslog.tls: true or false")
        else:
            try:
                parse_log_target(str(conf.get("url") or "") or "https://")
            except ValidationError as e:
                raise ValidationError(f"log_forwarding.elastic: {e}") from None
        for word in ("message_key", "index", "user"):
            if word in conf and not _WORD.match(str(conf[word])):
                raise ValidationError(f"log_forwarding.{part}.{word}: letters, digits and . _ @ -, at most 64")
        out[part] = conf
    return out


def _memory(value, have_gb):
    """Purpose: how many GB fabric may use (manual 1.2.4.2): a whole number from 4 to what the host has.
    Inputs:  value — the value given; have_gb — the host's GB (0: unknown, only the floor is checked).
    Returns: int.
    Fails:   ValidationError outside 4 to the host's GB, or for text.
    Feeds:   check_wizard_value."""
    if isinstance(value, bool) or not isinstance(value, int) or value < MIN_RAM_GB or (have_gb and value > have_gb):
        raise ValidationError(f"host_ram_capacity: a whole number of GB, {MIN_RAM_GB} to "
                              f"{have_gb or 'what the host has'}, not {value!r}")
    return value


def check_wizard_value(key, value, v, have_gb=0):
    """Purpose: one wizard setting checked as setup and its own page check it (manual 1.8.5.5), before anything
             changes: the parts and Kerberos true or false, the DNS filter bind or none,
             where the logs go (as setup asks it), the memory (4 to the host's GB), the password policy
             (check_password_policy, over today's, the default's keys filling in) and the DNS filter's
             upstreams (check_filter_settings).
    Inputs:  key — a WIZARD_KEYS name; value — the value given; v — the settings as saved (the password policy and
             the DNS filter's other settings the checks read); have_gb — the host's memory in GB (0: unknown).
    Returns: the value as it would be saved (normalised: the whole password policy, the upstreams' names in lower case).
    Fails:   ValidationError naming the key and why; KeyError for a key that is not the wizard's.
    Feeds:   plan_settings."""
    if key in ("install_fluentbit", "signin_kerberos"):
        return _flag(key, value)
    if key == "dns_filter":
        if str(value).lower() not in ("bind", "none") or not isinstance(value, str):
            raise ValidationError(f"dns_filter: bind (the DNS filter on) or none, not {value!r}")
        return value.lower()
    if key == "log_forwarding":
        return _log_forwarding(value)
    if key == "host_ram_capacity":
        return _memory(value, have_gb)
    if key == "ad_password_policy":
        if not isinstance(value, dict):
            raise ValidationError("ad_password_policy: a map of the policy's keys (minimum_length, complexity, ...)")
        policy = {**DEFAULT_POLICY, **(v.get("ad_password_policy") or {}), **value}
        try:
            check_password_policy(policy)
        except ValidationError as e:
            raise ValidationError(str(e) if "ad_password_policy" in str(e) else f"ad_password_policy: {e}") from None
        return policy
    if key == "dns_filter_upstreams":
        if not isinstance(value, list) or not all(isinstance(u, dict) and set(u) <= {"address", "name"}
                                                  for u in value):
            raise ValidationError("dns_filter_upstreams: a list of {address, name}")
        ups = [{"address": str(u.get("address") or ""), "name": str(u.get("name") or "").lower()} for u in value]
        check_filter_settings({**copy.deepcopy(v), "dns_filter_upstreams": ups})
        return ups
    raise KeyError(key)
