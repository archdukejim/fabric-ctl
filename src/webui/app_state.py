import threading
import time

from webui.constants import LOGIN_TTL
from webui.oidc import KeycloakOIDC
from webui.security.cert_subject_rfc2253 import cert_subject_rfc2253
from webui.security.parse_dn import parse_dn
from webui.tlsclient import TLSClient


class App:
    """The web UI's shared state: config, the Keycloak OIDC client, the expected client-certificate issuer, and the
    in-memory sessions and pending logins (a restart signs everyone out)."""

    def __init__(self, cfg):
        """Purpose: Hold the web UI's shared state.
        Inputs:  cfg — dict from webui.json: public_url, ca_file, intermediate_ca, admin_role, client_cert (default
                 true: a client certificate is required; false when webui_client_cert is off), session_idle (default
                 900 s), session_max (default 28800 s), keycloak {ip, port (default 8443), hostname, realm,
                 client_id, client_secret}.
        Returns: None (constructor); sets oidc, sso_origin, admin_role, client_cert, issuer_dn, idle, max_age,
                 sessions {sid: session}, pending {state: login}, lock.
        Fails:   KeyError for a missing required config key; ValueError from int() on bad session limits;
                 CalledProcessError from cert_subject_rfc2253. All stop the server at start.
        Feeds:   server.main, which sets it as Handler.app for every request.
        Notes:   admin_role names the admin bundle's role (webui.json); access is decided by the fabric:
                 permission roles in the token, and a person with none sees My account only (2.1.8.11).
        """
        self.cfg = cfg
        kc = cfg["keycloak"]
        self.public_url = cfg["public_url"].rstrip("/")
        self.oidc = KeycloakOIDC(
            TLSClient(kc["ip"], kc.get("port", 8443), kc["hostname"], cfg["ca_file"]),
            public_base=f"https://{kc['hostname']}", realm=kc["realm"],
            client_id=kc["client_id"], client_secret=kc["client_secret"],
            redirect_uri=f"{self.public_url}/oidc/callback")
        self.sso_origin = f"https://{kc['hostname']}"
        self.admin_role = cfg["admin_role"]
        self.client_cert = bool(cfg.get("client_cert", True))     # absent = the stricter way (0.6.0's)
        self.issuer_dn = parse_dn(cert_subject_rfc2253(cfg["intermediate_ca"]))
        self.idle = int(cfg.get("session_idle", 900))
        self.max_age = int(cfg.get("session_max", 28800))
        self.sessions = {}
        self.pending = {}
        self.lock = threading.Lock()

    def sweep(self):
        """Purpose: Drop expired sessions (idle longer than idle or older than max_age) and login attempts older than
                 LOGIN_TTL (600 s).
        Inputs:  none (reads and changes self.sessions and self.pending under self.lock).
        Returns: None.
        Fails:   never.
        Feeds:   handler.Handler.handle_request, at the start of every request.
        """
        now = time.time()
        with self.lock:
            for sid, s in list(self.sessions.items()):
                if now - s["last"] > self.idle or now - s["created"] > self.max_age:
                    del self.sessions[sid]
            for k, p in list(self.pending.items()):
                if now - p["created"] > LOGIN_TTL:
                    del self.pending[k]
