import os
import stat

from fabriclib.backup.check_bundle import check_bundle
from fabriclib.backup.check_changes import CHANGEABLE, NETWORK
from fabriclib.backup.check_whole_restore import check_whole_restore
from fabriclib.backup.make_bundle import FOLDER
from fabriclib.backup.receive_upload import receive_upload
from fabriclib.backup.list_bundles import list_bundles
from fabriclib.common.ask import ask, ask_secret
from fabriclib.common.errors import ValidationError
from fabriclib.setup.errors import SetupError
from fabriclib.setup.site.close_upload_dir import close_upload_dir
from fabriclib.setup.site.open_upload_dir import open_upload_dir

LABELS = {"host_ip": "The host's address", "lan_cidr": "Its subnet", "lan_gateway": "The subnet's gateway",
          "dns_server": "The upstream DNS server"}


def _take_upload(path, folder, receive=receive_upload):
    """Purpose: an upload the listener saved, taken out of its folder into the backups folder as root's own file
             (manual 1.3.7.10): copied through receive_upload, which checks it whole, then the listener's copy removed;
             nothing is read through a link or from anything but a plain file.
    Inputs:  path — the file in the upload folder; folder — the backups folder; receive — receive_upload (tests).
    Returns: the bundle's path in the backups folder.
    Fails:   ValidationError: receive_upload's (not a bundle's name, already there, not whole), or not a plain file;
             OSError. The listener's copy is removed either way.
    Feeds:   _pick_bundle."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
        with os.fdopen(fd, "rb") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise ValidationError("the upload is not a plain file")
            out = receive(os.path.basename(path), iter(lambda: f.read(1 << 20), b""), folder=folder)
    finally:
        if os.path.lexists(path):
            os.remove(path)
    return os.path.join(folder, out["file"])


def _pick_bundle(folder, bundles, upload_dir=None):
    """Purpose: the bundle to restore: one of the backups folder's, by its number, a path typed, or (on the site) an
             upload, whose answer is its path in the upload folder.
    Inputs:  folder — the backups folder; bundles — list_bundles(folder); upload_dir — the upload folder, or None.
    Returns: (path, manifest) of a whole bundle (check_bundle passed).
    Fails:   never for a bad answer: it is said, and asked again.
    Feeds:   ask_restore."""
    usable = [b for b in bundles if not b["error"]]
    if bundles:
        print(f"\n  Bundles in {folder}:")
        for n, b in enumerate(bundles, 1):
            what = b["error"] or f"fabric {b['fabric_version']}, {b['kind']}, {round(b['size'] / (1 << 20), 1)} MiB"
            print(f"    {n}. {b['file']}  ({what})")
    else:
        print(f"\n  No bundle is in {folder}: copy one there (root, 0600), or type its path on this host.")
    default = str(bundles.index(usable[0]) + 1) if usable else None
    while True:
        answer = ask("restore.bundle", "The bundle: its number, or its path on this host"
                     + (f" [{default}]" if default else "") + ": ", default).strip()
        path = bundles[int(answer) - 1]["path"] if answer.isdigit() and 0 < int(answer) <= len(bundles) else answer
        if upload_dir and path and os.path.dirname(os.path.abspath(path)) == os.path.abspath(upload_dir):
            try:
                path = _take_upload(path, folder)
                print(f"  {os.path.basename(path)} uploaded, whole, and kept in {folder}")
            except (ValidationError, OSError) as exc:
                print(f"  The upload cannot be restored: {exc}. Nothing of it is kept.")
                continue
        if not path or not os.path.isfile(path):
            print(f"  {answer!r}: not a bundle listed, nor a file on this host")
            continue
        try:
            return path, check_bundle(path)
        except (ValidationError, OSError) as exc:
            print(f"  {os.path.basename(path)} cannot be restored: {exc}")


def _show(path, manifest):
    """Purpose: the bundle's manifest, as the person checks it before giving its key (manual 1.3.7.10 step 2).
    Inputs:  path — the bundle; manifest — check_bundle's.
    Returns: None (printed: on the site, the next question's notes).
    Fails:   never.
    Feeds:   ask_restore."""
    sections = ", ".join(s["name"] for s in manifest.get("sections", []) if not s.get("empty"))
    print(f"\n  {os.path.basename(path)}: whole, each section's SHA-256 as its manifest says")
    for label, value in (("host", manifest.get("host")), ("domain", manifest.get("domain")),
                         ("addresses", f"{manifest.get('host_ip')} in {manifest.get('lan_cidr')}, gateway "
                                       f"{manifest.get('lan_gateway')}"),
                         ("made", f"{manifest.get('made')} by fabric {manifest.get('fabric_version')}"),
                         ("sealed", "with a passphrase" if manifest.get("opened_by") == "passphrase"
                          else "to the schedule's public key"),
                         ("sections", sections)):
        print(f"    {label + ':':11} {value}")


def ask_restore(ctx, package_version, folder=FOLDER, bundles=list_bundles, check=check_whole_restore,
                upload_dir=None):
    """Purpose: Guided's Restore from a backup (manual 1.3.7.10): the bundle, its manifest shown, its key, the
             address changes (1.3.7.7), all checked before anything is unpacked, then the plan and its one Proceed.
             The key stays in memory (ctx.restore_key), handed to the setup worker as the first admin's password is.
    Inputs:  ctx — SetupContext (deploy_base, vars_file); package_version — this package's fabric version; folder —
             the backups folder; bundles, check — list_bundles and check_whole_restore (tests give their own);
             upload_dir — on the site, the upload folder, made for the bundle's question and removed after it.
    Returns: {"bundle": path, "changes": {key: value}, "allow_again": bool} for the run's record; ctx.restore_key set
             to {"passphrase", "private_key"}.
    Fails:   SetupError: fabric is installed here (restore by the console or `fabricctl reinstall --from`), or Quit
             at the plan (nothing changed). A wrong key or a refused change is said and asked again.
    Feeds:   setup/run_setup (on the site, after its first choice)."""
    if os.path.exists(ctx.vars_file):
        raise SetupError("fabric is installed here: restore a bundle from the console (Settings · Backups) or with "
                         "sudo fabricctl reinstall --from <bundle> (manual 4.3.7.6)")
    try:
        if upload_dir:
            open_upload_dir(upload_dir)
        path, manifest = _pick_bundle(folder, bundles(folder), upload_dir)
    finally:
        if upload_dir:
            close_upload_dir(upload_dir)
    _show(path, manifest)
    while True:
        line = ask_secret("restore.key", "The bundle's passphrase, or for a scheduled bundle the private key line "
                                         "(AGE-SECRET-KEY-1…): ").strip()
        key = ({"passphrase": None, "private_key": line} if line.startswith("AGE-SECRET-KEY-1")
               else {"passphrase": line, "private_key": None})
        print("\n  The addresses this install comes back on: the bundle's, or a new network's (this host must have "
              "the new address already, manual 4.2.4.8).")
        new = {k: ask(f"restore.{k}", f"{LABELS[k]} [{manifest.get(k)}]: ", str(manifest.get(k))).strip()
               for k in CHANGEABLE if manifest.get(k)}
        changes = {k: v for k, v in new.items() if v != str(manifest.get(k))}
        try:
            check(ctx.deploy_base, path, key, package_version, changes)
            break
        except ValidationError as exc:
            print(f"\n  Refused, nothing changed: {exc}. Give the key and the addresses again.")
    moving = bool(set(changes) & set(NETWORK))
    print(f"\n  The plan: restore {os.path.basename(path)} whole, then set fabric up on it.")
    print("    Comes back as it was: the domain and its members, the CA, DNS, the vault, sign-in, DHCP, the settings.")
    for k, v in changes.items():
        print(f"    {k}: {manifest.get(k)} -> {v}")
    if moving:
        print("    Proceed also allows again, for the new network, the host changes allowed when the bundle was made "
              "(the firewall's and the ports' networks, the domain member's address); ones declined stay declined.")
    print("    A dropped browser or terminal does not stop it: it runs as fabric-setup.service.")
    if ask("restore.plan", "[P]roceed or [Q]uit? ", "q").strip().lower() not in ("p", "proceed"):
        raise SetupError("stopped at the plan: nothing was restored or changed")
    ctx.restore_key = key
    return {"bundle": path, "changes": changes, "allow_again": moving}
