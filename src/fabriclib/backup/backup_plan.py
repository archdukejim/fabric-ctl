import functools
import os

from fabriclib.backup.dump_directory import dump_directory
from fabriclib.backup.dump_signin import dump_signin
from fabriclib.backup.freeze_zones import freeze_zones
from fabriclib.backup.pause_unit import pause_unit
from fabriclib.backup.save_vault_snapshot import save_vault_snapshot
from fabriclib.backup.section_paths import section_paths
from fabriclib.backup.sections import ORDER

DUMPS = "/run/fabric/backup/dumps"       # RAM: an online section's dumps, packed under this path, then removed


def _live(section, base, v):
    """Purpose: the folders an online copy leaves out of a section because its service's dump stands for them.
    Inputs:  section — name; base — install root; v — vars.
    Returns: [abs path] (the DC's databases, OpenBao's raft data, Postgres's data folder).
    Fails:   never.
    Feeds:   backup_plan."""
    return {"directory": [os.path.join(base, "samba", "data")],
            "secrets": [os.path.join(base, "openbao", "data")],
            "signin": [os.path.normpath(v["postgres_data_dir"])] if v.get("postgres_data_dir") else [],
            }.get(section, [])


def backup_plan(base, v, method, dumps=DUMPS):
    """Purpose: what make_bundle packs, section by section (manual 1.3.7.4): cold, every section's folders as they
             are (fabric is stopped); online, the same less each live database, with its service's own consistent
             dump beside it, Step-CA paused and BIND's zones frozen for their copy.
    Inputs:  base — install root; v — vars.yaml as a dict; method — "cold" or "online"; dumps — the RAM folder online
             dumps are written to (one subfolder per section).
    Returns: [(section, paths, extra_dir, around)] for every section (make_bundle's plan). Online dumps are taken
             here, before any section is packed.
    Fails:   ValidationError from the dumps (the DC, Postgres or OpenBao not answering); ValueError for another method.
    Feeds:   make_backup."""
    if method not in ("cold", "online"):
        raise ValueError(f"unknown backup method {method!r}")
    plan = []
    for section in ORDER:
        paths = section_paths(section, base, v)
        extra = around = None
        if method == "online":
            live = _live(section, base, v)
            paths = [(p, skip + [x for x in live if x.startswith(p + os.sep)]) for p, skip in paths if p not in live]
            folder = os.path.join(dumps, section)
            if section == "directory" and os.path.isdir(os.path.join(base, "samba", "data")):
                dump_directory(base, folder)
                extra = folder
            elif section == "signin" and v.get("install_keycloak"):
                os.makedirs(folder, mode=0o700, exist_ok=True)
                dump_signin(os.path.join(folder, "keycloak.pgdump"))
                extra = folder
            elif section == "secrets" and os.path.isdir(os.path.join(base, "openbao", "data")):
                os.makedirs(folder, mode=0o700, exist_ok=True)
                save_vault_snapshot(v, os.path.join(folder, "openbao.snap"))
                extra = folder
            elif section == "pki":
                around = functools.partial(pause_unit, "stepca")
            elif section == "dns":
                around = freeze_zones
        plan.append((section, paths, extra, around))
    return plan
