import base64
import collections.abc
import json
import os
import posixpath
import re
import shlex
import time

import jinja2
import yaml

from fabriclib.common.lock_dir import lock_dir
from fabriclib.common.read_images_lock import read_images_lock
from fabriclib.common.read_packages_lock import read_packages_lock
from fabriclib.common.read_published_lock import read_published_lock
from fabriclib.dhcp.kea_client_classes import kea_client_classes
from fabriclib.dhcp.kea_option_data import kea_option_data
from fabriclib.dhcp.kea_option_defs import kea_option_defs
from fabriclib.images.published_image import published_image
from fabriclib.system.memory_limit_mb import memory_limit_mb
from fabriclib.system.plan_memory import plan_memory


class _RelativeEnvironment(jinja2.Environment):
    """Resolve `{% extends "../shared/base.html.j2" %}` relative to the
    including template."""

    def join_path(self, template, parent):
        """Purpose: let a template extend or include another by a path relative to itself
                 (`{% extends "../shared/base.html.j2" %}`).
        Inputs:  template — str, the name as written in the template; parent — str, the including template's name.
        Returns: str, the normalized loader path for "./" or "../" names; any other name unchanged.
        Fails:   never — string manipulation only.
        Feeds:   jinja2's loader (called by Environment.get_template for extends/include/import)."""
        if template.startswith(("./", "../")):
            return posixpath.normpath(posixpath.join(posixpath.dirname(parent), template))
        return template


def _unique(items, attribute=None):
    """Purpose: the Ansible-style `unique` filter: drop repeated items, keeping the first of each.
    Inputs:  items — iterable or None (None is treated as empty); attribute — optional str: for dict items,
             compare on item[attribute] (the whole item when the key is missing).
    Returns: list of the kept items in their original order.
    Fails:   TypeError if an item (or its compared value) is unhashable and not a dict or list.
    Feeds:   templates using `| unique` (rendered via jinja_env)."""
    seen, out = set(), []
    for item in items or []:
        val = item.get(attribute, item) if isinstance(item, dict) and attribute else item
        key = json.dumps(val, sort_keys=True) if isinstance(val, (dict, list)) else val
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def _flatten(value):
    """Purpose: the Ansible-style `flatten` filter: flatten nested lists and tuples to any depth.
    Inputs:  value — iterable; strings, bytes and dicts are kept as single items.
    Returns: list of the leaf items in order.
    Fails:   TypeError if value is not iterable; RecursionError on a self-containing list.
    Feeds:   templates using `| flatten`."""
    out = []
    for item in value:
        if isinstance(item, collections.abc.Iterable) and not isinstance(item, (str, bytes, dict)):
            out.extend(_flatten(item))
        else:
            out.append(item)
    return out


def _bool(value):
    """Purpose: the Ansible-style `bool` filter.
    Inputs:  value — any: bool as is; str true when one of true/yes/1/on/t/y (case-insensitive); other values
             by Python truthiness.
    Returns: bool.
    Fails:   never.
    Feeds:   templates using `| bool` (e.g. vars.yaml.j2)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "yes", "1", "on", "t", "y")
    return bool(value)


def _lookup(kind, arg):
    """Purpose: the one Ansible `lookup()` fabric's templates use: pipe('date +%s'), the current time.
    Inputs:  kind — str, must be "pipe"; arg — str, must be "date +%s".
    Returns: str, Unix time in seconds for that one call; "" for any other kind or argument (no command runs).
    Fails:   never.
    Feeds:   templates calling lookup(...) (global of jinja_env)."""
    if kind == "pipe" and arg == "date +%s":
        return str(int(time.time()))
    return ""


def jinja_env(template_dir):
    """Purpose: build the Jinja2 environment every fabric template is rendered with: fabric's Ansible-style
             filters, the `match` test, relative extends, trim_blocks/lstrip_blocks, trailing newlines kept.
    Inputs:  template_dir — str, the jinja folder (templates); its parent holds images.lock.yaml (an installed
             tree), or the parent's config/ does (the repository).
    Returns: jinja2.Environment with globals images_lock ({name: ref}), packages_lock, published_lock ({name: ref or
             ""}), published_ref(name) (the published image a host runs, or "": images/published_image), lookup and
             the Kea helpers (kea_option_data, kea_option_defs, kea_client_classes), plan_memory (the memory budget)
             and memory_mb(service) (that service's limit in MB from the template's context).
    Fails:   yaml.YAMLError or OSError from read_images_lock / read_packages_lock if images.lock.yaml is
             unreadable; KeyError from read_images_lock if an image entry lacks repo, tag or digest.
             A missing lock file gives empty globals, not an error.
    Feeds:   deploy/apply_deployment (and render_templates), dhcp/deploy_kea.py, logs/deploy_fluentbit.py,
             logs/run_logs_command.py,
             radius/deploy_freeradius.py; tests/render.py and the kea, fluentbit and freeradius suites."""
    # pages (*.html.j2) escape every value; other files quote values for their language: `to_json` for YAML and
    # JSON, `sh` for shell (manual 1.1.5.7)
    env = _RelativeEnvironment(loader=jinja2.FileSystemLoader(template_dir), keep_trailing_newline=True,
                               trim_blocks=True, lstrip_blocks=True,
                               autoescape=jinja2.select_autoescape(enabled_extensions=("html.j2",), default=False))
    env.filters.update({
        "to_nice_yaml": lambda v, indent=4: yaml.safe_dump(v, default_flow_style=False, indent=indent).strip(),
        "to_json": json.dumps,
        "sh": lambda v: shlex.quote(str(v)),
        "unique": _unique,
        "regex_replace": lambda s, pattern, repl: re.sub(pattern, repl, s),
        "b64encode": lambda s: base64.b64encode(s.encode()).decode(),
        "flatten": _flatten,
        "bool": _bool,
        "dirname": os.path.dirname,
        "basename": os.path.basename,
        "combine": lambda base, *others: {k: v for d in (base, *others) for k, v in (d or {}).items()},
    })
    env.tests["match"] = lambda value, pattern: bool(re.search(pattern, str(value)))
    env.globals["lookup"] = _lookup
    # Kea (manual 1.10.2): fabric's option format to Kea's JSON, one helper per Kea list
    env.globals.update(kea_option_data=kea_option_data, kea_option_defs=kea_option_defs,
                       kea_client_classes=kea_client_classes)
    # image_* defaults: the validated, digest-pinned refs — fabric/images.lock.yaml on a host, config/ in the repository
    locks = lock_dir(template_dir)
    env.globals["images_lock"] = {k: e["ref"] for k, e in read_images_lock(locks).items()}
    env.globals["packages_lock"] = read_packages_lock(locks)
    # fabric's own published images (manual 1.14.3): image_fabric_* defaults, and which one a host runs
    published = (read_published_lock(locks) or {}).get("images") or {}
    env.globals["published_lock"] = {k: e["ref"] for k, e in published.items()}
    env.globals["published_ref"] = jinja2.pass_context(
        lambda ctx, name: published_image(ctx, published[name]) if name in published else "")
    # memory as a budget (manual 1.2.4.3): vars.yaml.j2 plans it, each compose file takes its service's limit
    env.globals["plan_memory"] = plan_memory
    env.globals["memory_mb"] = jinja2.pass_context(memory_limit_mb)
    return env
