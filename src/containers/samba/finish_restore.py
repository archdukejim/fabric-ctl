"""Run in the DC's image with the DC stopped (manual 1.3.7.6): remove the marks Samba's offline backup leaves on the
copied sam.ldb, with which Samba refuses to start. `docker compose run --rm --no-deps --entrypoint python3 samba
/fabric/finish_restore.py`; fabric/backup/load_directory_dump runs it."""
import sys

import ldb
from samba.param import LoadParm

MARKS = ("sidForRestore", "backupRename", "backupDate", "backupType")


def finish_restore(conf="/data/etc/smb.conf"):
    """Purpose: the backup marks removed from @SAMBA_DSDB of the restored sam.ldb, as `samba-tool domain backup restore`
             does, without that tool's new DC name (fabric never renames its DC, 2.1.6.45).
    Inputs:  conf — the DC's smb.conf (its private dir names sam.ldb). The file is opened as a plain ldb, without
             Samba's modules: @SAMBA_DSDB is a record of sam.ldb itself (ldb.Ldb takes no session or LoadParm, unlike
             SamDB: found 2026-11-23 by the sandbox's whole restore).
    Returns: the marks removed, list of str (empty: none was there).
    Fails:   ldb.LdbError when sam.ldb cannot be opened (the DC is running and holds it, or the copy is not there).
    Feeds:   main."""
    lp = LoadParm()
    lp.load(conf)
    db = ldb.Ldb(url=lp.private_path("sam.ldb"), flags=ldb.FLG_DONT_CREATE_DB, options=["modules:"])
    found = db.search(base=ldb.Dn(db, "@SAMBA_DSDB"), scope=ldb.SCOPE_BASE, attrs=list(MARKS))
    m = ldb.Message()
    m.dn = ldb.Dn(db, "@SAMBA_DSDB")
    removed = [a for a in MARKS if found and a in found[0]]
    for attr in removed:
        m[attr] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE, attr)
    if removed:
        db.modify(m)
    return removed


def main():
    """Purpose: the tool's entry: prints what it removed.
    Inputs:  none.
    Returns: exit status 0, 1 when sam.ldb cannot be opened (the reason printed).
    Fails:   never raises.
    Feeds:   the command line above."""
    try:
        removed = finish_restore()
    except ldb.LdbError as exc:
        print(f"the restored domain could not be opened: {exc}", file=sys.stderr)
        return 1
    print("backup marks removed: " + (", ".join(removed) or "none were there"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
