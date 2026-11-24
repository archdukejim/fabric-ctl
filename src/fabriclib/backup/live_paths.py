import os


def live_paths(section, base, v):
    """Purpose: the folders an online copy leaves out of a section because its service's dump stands for them.
    Inputs:  section — name; base — install root; v — vars.
    Returns: [abs path] (OpenBao's raft data, Postgres's data folder). The DC's databases are left out by name
             instead (DC_DATABASES): SYSVOL and the DLZ's files beside them are packed live.
    Fails:   never.
    Feeds:   backup_plan (left out of the copy), restore_section (left in place: the dump is loaded into the
             running database)."""
    return {"secrets": [os.path.join(base, "openbao", "data")],
            "signin": [os.path.normpath(v["postgres_data_dir"])] if v.get("postgres_data_dir") else [],
            }.get(section, [])
