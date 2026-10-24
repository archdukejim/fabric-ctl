"""A person's session in fabric's console, driven like a browser (manual 3.1.5.10): nginx's TLS verified against
fabric's root CA, Keycloak's sign-in pages filled in (password, a forced change after a reset), the OIDC callback,
then the console's pages and forms. Runs as root on the fabric host, as tests/sandbox/login_test.py does (whose
browser this follows), reading the host's settings for the names and addresses.

    from console_session import Console
    c = Console(vars_dict); st, page = c.login("lab.admin", password); st, loc, page = c.get("/networks")
"""
import html
import http.client
import os
import re
import secrets
import socket
import ssl
import time
import urllib.parse


def form_fields(page, action_prefix=""):
    """Purpose: the first form of a page whose action starts with action_prefix, as Keycloak's or the console's.
    Inputs:  page — HTML; action_prefix — str ("" for the first form).
    Returns: (action or None, {input name: value}) — hidden and text inputs with their values.
    Fails:   never.
    Feeds:   Console.login, the lab's console checks."""
    for m in re.finditer(r'<form([^>]*)>(.*?)</form>', page, re.I | re.S):
        act = re.search(r'action="([^"]+)"', m.group(1), re.I)
        action = html.unescape(act.group(1)) if act else None
        if action is None or not action.startswith(action_prefix):
            continue
        fields = {}
        for tag in re.findall(r"<input[^>]*>", m.group(2), re.I):
            n = re.search(r'name="([^"]+)"', tag, re.I)
            if n:
                val = re.search(r'value="([^"]*)"', tag)
                fields[n.group(1)] = html.unescape(val.group(1)) if val else ""
        return action, fields
    return None, {}


class Console:
    """Per-host cookies, manual redirects, TLS verified against fabric's root CA; one person's console session."""

    def __init__(self, v):
        """Purpose: a session against this host's console.
        Inputs:  v — the host's settings (vars.yaml): hostname_mgr, hostname_keycloak, ip_nginx, deploy_base_dir.
        Returns: Console.
        Fails:   OSError when fabric's root CA cannot be read."""
        self.mgr, self.sso, self.nginx = v["hostname_mgr"], v["hostname_keycloak"], v["ip_nginx"]
        self.ctx = ssl.create_default_context(
            cafile=os.path.join(v["deploy_base_dir"], "stepca", "data", "certs", "root_ca.crt"))
        self.cookies, self.new_pw = {}, None

    def request(self, method, url, form=None):
        """Purpose: one request, as a browser would send it (its cookies, an Origin on a form).
        Inputs:  method — GET or POST; url — absolute; form — dict to post urlencoded, or None.
        Returns: (status, absolute Location or None, body text).
        Fails:   OSError on a connection or TLS failure (a certificate fabric's CA did not sign among them)."""
        u = urllib.parse.urlsplit(url)
        conn = http.client.HTTPSConnection(self.nginx, 443, timeout=60)
        conn.sock = self.ctx.wrap_socket(socket.create_connection((self.nginx, 443), 60), server_hostname=u.hostname)
        jar = self.cookies.setdefault(u.hostname, {})
        headers = {"Host": u.hostname}
        if jar:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Origin"] = f"https://{u.hostname}"
        conn.request(method, u.path + (f"?{u.query}" if u.query else ""), body=body, headers=headers)
        resp = conn.getresponse()
        for k, val in resp.getheaders():
            if k.lower() == "set-cookie":
                name, _, rest = val.partition("=")
                value = rest.split(";", 1)[0]
                if value and "Max-Age=0" not in val:
                    jar[name] = value
                else:
                    jar.pop(name, None)
        data = resp.read().decode(errors="replace")
        loc = resp.getheader("Location")
        conn.close()
        return resp.status, (urllib.parse.urljoin(url, loc) if loc else None), data

    def get(self, path):
        """Purpose: a console page. Inputs: path — "/networks?site=…". Returns: (status, Location, body)."""
        return self.request("GET", f"https://{self.mgr}{path}")

    def post(self, path, form):
        """Purpose: a console form, with the session's CSRF token added, and the page it leads back to.
        Inputs:  path — the form's action; form — its fields.
        Returns: (status of the POST, ("ok" | "bad" | "", the message the next page shows), that page or the
                 POST's own body when it did not redirect)."""
        st, loc, page = self.request("POST", f"https://{self.mgr}{path}", {"csrf": self.csrf(), **form})
        if st == 303 and loc:
            _, _, page = self.request("GET", loc)
        return st, flash(page), page

    def csrf(self):
        """Purpose: the session's CSRF token, read from a page that has a form. Returns: str ("" when none shown)."""
        _, _, page = self.get("/networks")
        m = re.search(r'name="csrf" value="([^"]+)"', page)
        return m.group(1) if m else ""

    def login(self, user, password):
        """Purpose: sign in through Keycloak as a person would: the password, a new one when a reset forces it.
        Inputs:  user — uid; password — the current password.
        Returns: (status of the OIDC callback, its page, the Keycloak pages seen).
        Fails:   OSError as request."""
        st, loc, page = self.request("GET", f"https://{self.mgr}/login")
        if not (st == 303 and loc and loc.startswith(f"https://{self.sso}/")):
            return st, f"login did not redirect to Keycloak: {loc}", []
        done, seen = f"https://{self.mgr}/oidc/callback", []
        st, loc, page = self.request("GET", loc)
        for _ in range(10):
            while st in (301, 302, 303) and loc and not loc.startswith(done):
                st, loc, page = self.request("GET", loc)
            if loc and loc.startswith(done):
                st, _, page = self.request("GET", loc)
                return st, page, seen
            action, fields = form_fields(page)
            if not action:
                return st, page, seen
            if set(fields) == {"continue"}:            # Kerberos offered (401 Negotiate) and none given: go on
                seen.append("no-kerberos")
            elif "username" in fields and "password" in fields:
                seen.append("login")
                fields.update(username=user, password=self.new_pw or password)
            elif "password-new" in fields:
                seen.append("update-password")
                self.new_pw = secrets.token_urlsafe(18)
                fields.update({"password-new": self.new_pw, "password-confirm": self.new_pw})
            elif {"firstName", "lastName", "email"} & set(fields):
                seen.append("update-profile")
            else:
                return st, f"unknown Keycloak page {sorted(fields)}", seen
            st, loc, page = self.request("POST", action, {k: x for k, x in fields.items() if k != "cancel-aia"})
        return st, page, seen

    def apply(self, page_id):
        """Purpose: Apply a page's held changes (manual 1.8.6.5) and wait on its Review until the job ends.
        Inputs:  page_id — "networks" or "options".
        Returns: (status, the Review page once it no longer refreshes; up to 4 minutes).
        Fails:   OSError as request."""
        st, _, page = self.request("POST", f"https://{self.mgr}/changes/{page_id}/apply", {"csrf": self.csrf()})
        if st != 303:
            return st, page
        for _ in range(120):
            st, _, page = self.get(f"/changes/{page_id}")
            if st != 200 or 'http-equiv="refresh"' not in page:
                return st, page
            time.sleep(2)
        return st, page


def flash(page):
    """Purpose: the outcome a console page shows after a form (base.html's flash: ok or bad).
    Inputs:  page — HTML.
    Returns: ("ok" | "bad" | "", its text unescaped)."""
    m = re.search(r'<p class="flash (ok|bad)" role="(?:status|alert)">(.*?)</p>', page, re.S)
    return (m.group(1), html.unescape(re.sub(r"<[^>]+>", "", m.group(2))).strip()) if m else ("", "")
