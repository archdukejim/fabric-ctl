import ipaddress
import time

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.radius.coa.attributes import (ACCT_SESSION_ID, CALLING_STATION_ID, COA_REQUEST, DISCONNECT_REQUEST,
                                             EVENT_TIMESTAMP, NAS_IP_ADDRESS, VENDOR_SPECIFIC, cisco_avpair, integer,
                                             ipv4, text)
from fabriclib.radius.coa.send_coa import send_coa
from fabriclib.radius.list_radius_sessions import list_radius_sessions
from fabriclib.radius.nas.nas_profile import nas_profile
from fabriclib.radius.nas.profiles import COA_ACTIONS, DEFAULT_VENDOR
from fabriclib.secrets.load_secrets import load_secrets

LABELS = {"disconnect": "Disconnect", "reauthenticate": "Re-authenticate", "bounce": "Move VLAN (bounce the port)"}


def coa_session(v, actor, action, client, session, source="cli", secrets=None, records=None, sender=send_coa):
    """Purpose: Disconnect a device's 802.1X session, or make it authenticate again (and, with bounce, ask DHCP again
             on its new VLAN), by sending its switch an RFC 5176 Disconnect-Request or CoA-Request (manual 1.11.1.4).
             Refused, with why and nothing sent, where the switch's vendor has no CoA.
    Inputs:  v — the vars dict (install_freeradius, radius_clients); actor — str (audit); action — "disconnect",
             "reauthenticate" or "bounce"; client — the RADIUS client's name; session — its Acct-Session-Id;
             source — "cli" or "web"; secrets — fabric's secrets dict (None: load_secrets()); records — passed to
             list_radius_sessions (None: the journal); sender — the function that sends (send_coa; tests pass their
             own).
    Returns: {"action", "client", "session", "mac", "who", "nas_ip", "port", "label", "message"} once the switch
             acknowledged it.
    Fails:   ValidationError with why, nothing sent: an unknown action; 802.1X off; no RADIUS client of that name; a
             vendor without CoA (the profile's no_coa: what to do instead); an action the vendor lacks; no open session
             with that id on that client; a NAS address outside the client's address; no shared secret for the
             client. ValidationError after sending: the switch refused (NAK, with its Error-Cause), answered with a
             bad signature, or did not answer (what to check). Each sent attempt is audited (RADIUS_COA) with its
             result. OSError from the socket; errors from load_secrets.
    Feeds:   agent routes POST /v1/radius/sessions/disconnect and /v1/radius/sessions/reauthenticate (fabric-agent,
             called by the web UI); run_radius_command (disconnect, reauthenticate).
    """
    if action not in COA_ACTIONS:
        raise ValidationError("action must be one of " + ", ".join(COA_ACTIONS))
    if not v.get("install_freeradius"):
        raise ValidationError("802.1X is off (install_freeradius: false)")
    name = str(client or "").strip().lower()
    entry = next((c for c in v.get("radius_clients") or [] if c.get("name") == name), None)
    if entry is None:
        raise ValidationError(f"no RADIUS client {name}")
    profile = nas_profile(entry.get("vendor") or DEFAULT_VENDOR)
    if not profile["coa"]:
        raise ValidationError(f"{name} is a {profile['vendor']} client: {profile['no_coa']}")
    how = profile["coa"]["actions"].get(action)
    if how is None:
        raise ValidationError(f"{LABELS[action]} is not something a {profile['vendor']} switch does")
    found = next((s for s in list_radius_sessions(records)
                  if s["client"] == name and s["session"] == str(session)), None)
    if found is None:
        raise ValidationError(f"no open session {session} on {name} (it ended, or its switch sends no accounting)")
    nas_ip = found["nas_ip"] if found["nas_ip"] not in ("", "-") else entry["address"]
    try:
        inside = ipaddress.ip_address(nas_ip) in ipaddress.ip_network(entry["address"], strict=False)
    except ValueError:
        inside = False
    if not inside:
        raise ValidationError(f"the session's NAS address {nas_ip} is not {name}'s address ({entry['address']}): "
                              "nothing sent")
    secret = ((load_secrets() if secrets is None else secrets).get("radius_secrets") or {}).get(name)
    if not secret:
        raise ValidationError(f"{name} has no shared secret in fabric's secrets: rotate it first")
    attrs = [(ACCT_SESSION_ID, text(found["session"])), (NAS_IP_ADDRESS, ipv4(nas_ip)),
             (EVENT_TIMESTAMP, integer(time.time()))]
    if found["mac"] not in ("", "-"):
        attrs.append((CALLING_STATION_ID, text(found["mac"].replace(":", "-").upper())))
    if how[0] == "coa":
        attrs.append((VENDOR_SPECIFIC, cisco_avpair(how[1])))
    code = DISCONNECT_REQUEST if how[0] == "disconnect" else COA_REQUEST
    reply = sender(nas_ip, profile["coa"]["port"], secret, code, attrs)
    result = "no answer" if reply is None else "ACK" if reply["ack"] else ("NAK " + (reply["error"] or "")).strip()
    write_audit(actor, "RADIUS_COA", f"client={name} session={found['session']} mac={found['mac']} action={action} "
                                     f"result={result.replace(' ', '_')}", source)
    if reply is None:
        raise ValidationError(f"{name} did not answer on UDP {profile['coa']['port']} at {nas_ip}: check that it "
                              "accepts CoA from this host with this secret (aaa server radius dynamic-author, "
                              "manual 4.11.1.3) and that nothing between drops it")
    if not reply["ack"]:
        raise ValidationError(f"{name} refused {LABELS[action]}: {reply['error'] or 'no reason given'}")
    return {"action": action, "client": name, "session": found["session"], "mac": found["mac"], "who": found["who"],
            "nas_ip": nas_ip, "port": found["port"], "label": LABELS[action],
            "message": f"{LABELS[action]}: {found['who']} ({found['mac']}) on {name} {found['port']}: acknowledged"}
