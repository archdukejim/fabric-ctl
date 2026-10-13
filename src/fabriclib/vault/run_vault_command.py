import getpass
import subprocess
import sys

from fabriclib.common.ask import ask_secret
from fabriclib.common.errors import ValidationError
from fabriclib.vault.add_kmip_slot import add_kmip_slot
from fabriclib.vault.common.approle_login import approle_login
from fabriclib.vault.common.wait_active import wait_active
from fabriclib.vault.constants import SETUP_CREDS
from fabriclib.vault.add_security_key_slot import add_security_key_slot
from fabriclib.vault.add_usb_slot import add_usb_slot
from fabriclib.vault.generate_root_token import generate_root_token
from fabriclib.vault.list_pkcs11_tokens import list_pkcs11_tokens
from fabriclib.vault.list_slots import list_slots
from fabriclib.vault.remove_slot import remove_slot
from fabriclib.vault.revoke_token import revoke_token
from fabriclib.vault.rotate_db_password import rotate_db_password
from fabriclib.vault.rotate_vault_key import rotate_vault_key
from fabriclib.vault.test_slot import test_slot
from fabriclib.vault.unlock_vault import unlock_vault
from fabriclib.vault.vault_device_event import vault_device_event
from fabriclib.vault.vault_status import vault_status
from fabriclib.vault.wipe_runtime_keys import wipe_runtime_keys

USAGE = """usage: fabricctl vault status
       fabricctl vault slots                 unlock methods (key slots)
       fabricctl vault test <slot>           unwrap the vault key through one method
       fabricctl vault remove <slot> --yes   remove a method (never the last)
       fabricctl vault rotate --yes          new vault key for every present method
       fabricctl vault rotate-db             Keycloak's database password, rotated now by OpenBao (the monthly
                                             fabric-db-rotate timer runs it with --scheduled)
       fabricctl vault add-usb <disk> [--label L] --yes   ERASE a USB stick and make it an unlock method
       fabricctl vault add-kmip <host:port> --key-id ID --ca FILE --cert FILE --key FILE
                                [--server-name NAME] [--label L] --yes
                                             an HSM / key manager (KMIP) as an unlock method
       fabricctl vault tokens                security keys the allowed PKCS#11 libraries see
       fabricctl vault add-key <serial> [--module LIB] [--key-id new|HEX] [--label L] --yes
                                             make a security key an unlock method (PIN asked, or on stdin)
       fabricctl vault break-glass [--restart]  root token from the recovery keys (keys asked, or on stdin)
       fabricctl vault revoke-token          revoke a token (asked, or on stdin) — after break-glass
       fabricctl vault unlock                (systemd) put the key in RAM for OpenBao's start
       fabricctl vault device-event          (udev) an unlock device came or went: start/stop OpenBao
       fabricctl vault wipe-key              (systemd) wipe it once OpenBao is unsealed"""


def restart_openbao(v, timeout=180):
    """Purpose: restart the openbao unit (its start condition runs fabric-unlock) and wait until OpenBao is active.
    Inputs:  v — vars; timeout — seconds, for systemctl and for wait_active (180).
    Returns: None.
    Fails:   subprocess.CalledProcessError if systemctl fails (e.g. fabric-unlock finds no method);
             subprocess.TimeoutExpired; ValidationError from wait_active.
    Feeds:   the restart callable of rotate_vault_key, from run_vault_command (rotate) and the agent route
             POST /v1/vault/rotate.
    """
    subprocess.run(["systemctl", "restart", "openbao"], check=True, timeout=timeout)
    wait_active(v, timeout)


def _status(v):
    """Purpose: print `fabricctl vault status`.
    Inputs:  v — vars.
    Returns: exit status: 0 when initialised and unsealed; 1 when unreachable, sealed or not initialised.
    Fails:   OpenBao errors are part of vault_status's result, not raised; OSError from its key-store check when not
             root.
    Feeds:   run_vault_command.
    """
    s = vault_status(v)
    if not s["reachable"]:
        print(f"OpenBao: unreachable — {s.get('error', '')}")
        return 1
    state = "not initialised" if not s["initialized"] else ("SEALED" if s["sealed"] else "unsealed")
    print(f"OpenBao {s['version']}: {state}  ({s['seal_type']} seal, {s['storage']} storage)  {s['url']}")
    print(f"unlock methods: {s['key']['detail']}")
    for m in s.get("mounts", []):
        print(f"  {m['path']:<12} {m['type']}{' v' + m['version'] if m['version'] else ''}  {m['description']}")
    if s.get("secrets"):
        print(f"fabric's secrets: in OpenBao (fabric/secrets, version {s['secrets']['version']}, "
              f"updated {s['secrets']['updated']})")
    if s.get("auth"):
        print(f"  auth: {', '.join(s['auth'])}")
    if s.get("error"):
        print(f"note: {s['error']}")
    return 0 if s["initialized"] and not s["sealed"] else 1


def run_vault_command(v, argv):
    """Purpose: `fabricctl vault ...`: OpenBao status and its unlock methods. Never prints key material.
    Inputs:  v — vars; argv — the words after `vault` (none: status). Subcommands: status, unlock, wipe-key, slots,
             test <slot>, remove <slot> --yes, device-event, add-usb <disk> [--label L] --yes,
             add-kmip <host:port> --key-id --ca --cert --key [--server-name] [--label] --yes, tokens,
             add-key <serial> [--module] [--key-id] [--label] --yes, break-glass [--restart], revoke-token,
             rotate --yes. PINs, recovery keys and tokens come from a prompt or stdin, never argv.
    Returns: exit status: 0 done; 1 a ValidationError (printed as "error: ..."), `unlock` with no method present
             (systemd then does not start OpenBao) or `status` not unsealed; 2 unknown command (usage printed).
    Fails:   ValidationError is caught and printed. Other exceptions propagate as a traceback, e.g. OSError reading a
             --ca/--cert/--key file, CalledProcessError from restart_openbao during rotate, IndexError for an option
             without its value.
    Feeds:   fabriclib/cli.py (`fabricctl vault`); the openbao unit runs `vault unlock` (start condition) and
             `vault wipe-key` (after start); the udev rules run `vault device-event`.
    """
    cmd, args = (argv[0], argv[1:]) if argv else ("status", [])
    try:
        if cmd == "status" and not args:
            return _status(v)
        if cmd == "unlock" and not args:
            res = unlock_vault(v)
            if res is None:
                print("no unlock method is present: OpenBao stays locked", file=sys.stderr)
                return 1
            print(f"vault key in place (via {res['slot']})" + (" — WARNING: unlock methods changed while locked"
                                                              if res["tamper"] else ""))
            return 0
        if cmd == "wipe-key" and not args:
            print(f"wiped {wipe_runtime_keys(v)} key file(s) from RAM")
            return 0
        if cmd == "slots" and not args:
            for sl in list_slots(v):
                print(f"{'●' if sl['present'] else '○'} {sl['id']:<12} {sl['type']:<7} {sl['key_id']:<10} "
                      f"{sl['label']}  {sl['device']}  [tested: {sl['tested']}]")
            return 0
        if cmd == "test" and len(args) == 1:
            test_slot(v, "root", args[0], source="cli")
            print(f"{args[0]}: unwrapped the vault key, check value matches")
            return 0
        if cmd == "remove" and len(args) == 2 and args[1] in ("--yes", "-y"):
            remove_slot(v, "root", args[0], source="cli")
            print(f"{args[0]}: removed")
            return 0
        if cmd == "device-event" and not args:
            print(vault_device_event(v))
            return 0
        if cmd == "add-usb" and args and "--yes" in args:
            label = args[args.index("--label") + 1] if "--label" in args else ""
            print(f"added {add_usb_slot(v, 'root', args[0], label, source='cli')}")
            return 0
        if cmd == "add-kmip" and args and "--yes" in args:
            opt = {k: args[args.index(k) + 1] for k in ("--key-id", "--ca", "--cert", "--key", "--server-name",
                                                        "--label") if k in args}
            missing = [k for k in ("--key-id", "--ca", "--cert", "--key") if k not in opt]
            if missing:
                raise ValidationError(f"missing {', '.join(missing)}")
            pems = {}
            for k in ("--ca", "--cert", "--key"):
                with open(opt[k]) as f:
                    pems[k] = f.read()
            print("added " + add_kmip_slot(v, "root", args[0], opt["--key-id"], pems["--ca"], pems["--cert"],
                                           pems["--key"], opt.get("--server-name", ""), opt.get("--label", ""),
                                           source="cli"))
            return 0
        if cmd == "tokens" and not args:
            for t in list_pkcs11_tokens(v):
                print(f"{t['serial']:<18} {t['manufacturer']} {t['model']}  label={t['label']!r}  "
                      f"PIN: {t['pin_state']}  ({t['module']})")
            return 0
        if cmd == "add-key" and args and "--yes" in args:
            opt = {k: args[args.index(k) + 1] for k in ("--module", "--key-id", "--label") if k in args}
            tokens = [t for t in list_pkcs11_tokens(v) if t["serial"] == args[0]
                      and opt.get("--module", t["module"]) == t["module"]]
            if len(tokens) != 1:
                raise ValidationError(f"{len(tokens)} tokens with serial {args[0]!r}: see `fabricctl vault tokens`"
                                      + (" and pass --module" if tokens else ""))
            # the PIN never goes on the command line (argv is world-readable)
            pin = (ask_secret("vault.token_pin", "token PIN: ") if sys.stdin.isatty()
                   else sys.stdin.readline().rstrip("\n"))
            print("added " + add_security_key_slot(v, "root", tokens[0]["module"], args[0], pin,
                                                   opt.get("--key-id", "new"), opt.get("--label", ""), source="cli"))
            return 0
        if cmd == "break-glass" and args in ([], ["--restart"]):
            # recovery keys and the token never go on a command line
            if sys.stdin.isatty():
                keys = []
                while len(keys) < 10:
                    key = ask_secret("vault.recovery_key",
                                     f"recovery key {len(keys) + 1} (empty line when done): ").strip()
                    if not key:
                        break
                    keys.append(key)
            else:
                keys = [line.strip() for line in sys.stdin if line.strip()]
            token = generate_root_token(v, "root", keys, restart=bool(args))
            print("ROOT TOKEN (shown once; full power over OpenBao — revoke it as soon as you are done):")
            print(f"  {token}")
            print("revoke: sudo fabricctl vault revoke-token   (paste it)")
            return 0
        if cmd == "revoke-token" and not args:
            token = ask_secret("vault.root_token", "token: ") if sys.stdin.isatty() else sys.stdin.readline().strip()
            if not revoke_token(v, token):
                raise ValidationError("the token still works (or OpenBao refused): not revoked")
            print("revoked")
            return 0
        if cmd == "rotate-db" and args in ([], ["--scheduled"]):
            if not v.get("install_keycloak"):
                print("no Keycloak on this host: nothing to rotate")
                return 0
            rotate_db_password(v, approle_login(v, SETUP_CREDS), actor=getpass.getuser(),
                               source="timer" if args else "cli")
            print("Keycloak's database password rotated; Keycloak restarted with it and healthy")
            return 0
        if cmd == "rotate" and args in (["--yes"], ["-y"]):
            res = rotate_vault_key(v, "root", lambda: restart_openbao(v), source="cli")
            print(f"vault key rotated to {res['key_id']}; kept {', '.join(res['kept'])}"
                  + (f"; dropped {', '.join(res['dropped'])}" if res["dropped"] else ""))
            return 0
    except ValidationError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(USAGE, file=sys.stderr)
    return 2
