from fabriclib.radius.nas.profiles import PROFILES, RADSEC_CN_PREFIX, RADSEC_PORT, RADSEC_SECRET

SECRET_PLACEHOLDER = "<SHARED-SECRET>"      # never the secret itself: it is shown once, on its own page


def cisco_snippet(v, client):
    """Purpose: the IOS-XE configuration for one Cisco RADIUS client (manual 4.11.1.3), filled in for this install,
             with the shared secret left out: the page shows SECRET_PLACEHOLDER where the admin types it, so the
             secret is never in a page, a log or a file fabric writes (it is shown once when made).
    Inputs:  v — the vars dict (host_ip, hostname_radius); client — a radius_clients entry (name, transport).
    Returns: str, the configuration (global configuration mode), with comments ("!") saying what each part is for.
    Fails:   KeyError if client has no "name".
    Feeds:   radius_guides (the FreeRADIUS tab's Connect a switch view); tests/freeradius/nas_profiles_test.py.
    Notes:   untested on a Cisco switch (2.3.11.5): written from Cisco's IOS-XE 17 guides; the access-port part uses
             the classic `authentication` commands, which a switch converted to the new style (IBNS 2.0) takes as
             `access-session` policies instead.
    """
    host, name = v.get("host_ip", "<fabric-host-ip>"), client["name"]
    server = v.get("hostname_radius", "radius.<domain>")
    port = PROFILES["cisco"]["coa"]["port"]
    lines = ["! fabric 802.1X for " + name + " (IOS-XE). Type the shared secret where it says " + SECRET_PLACEHOLDER,
             "! (shown once when the client was added in fabric; lost: New secret). Keep it out of the clear config:",
             "password encryption aes",
             "! (key config-key password-encrypt asks for its master key at the prompt)",
             "aaa new-model"]
    if client.get("transport") == "radsec":
        lines += ["!",
                  "! RadSec: the switch's own key and certificate (CN " + RADSEC_CN_PREFIX + name
                  + ") from fabric's CA",
                  "crypto key generate rsa label fabric-radsec modulus 2048",
                  "crypto pki trustpoint fabric-root",
                  " enrollment terminal pem",
                  " revocation-check none",
                  "crypto pki authenticate fabric-root",
                  "! paste fabric's root CA (Step-CA tab, or http://<ca>/certs/root_ca.crt)",
                  "crypto pki trustpoint fabric-radsec",
                  " enrollment terminal pem",
                  " subject-name CN=" + RADSEC_CN_PREFIX + name,
                  " rsakeypair fabric-radsec",
                  " chain-validation continue fabric-root",
                  " revocation-check none",
                  "crypto pki authenticate fabric-radsec",
                  "! paste fabric's intermediate CA",
                  "crypto pki enroll fabric-radsec",
                  "! copy the request it prints, sign it on fabric's Step-CA tab (Sign a CSR), then:",
                  "crypto pki import fabric-radsec certificate",
                  "! paste the signed certificate",
                  "!",
                  "radius server fabric",
                  " address ipv4 " + host + " auth-port " + str(RADSEC_PORT) + " acct-port " + str(RADSEC_PORT),
                  " tls connectiontimeout 5",
                  " tls idletimeout 60",
                  " tls trustpoint client fabric-radsec",
                  " tls trustpoint server fabric-radsec",
                  " tls match-server-identity hostname " + server,
                  " key " + RADSEC_SECRET]
    else:
        lines += ["!",
                  "radius server fabric",
                  " address ipv4 " + host + " auth-port 1812 acct-port 1813",
                  " key " + SECRET_PLACEHOLDER]
    lines += ["!",
              "aaa group server radius FABRIC",
              " server name fabric",
              "aaa authentication dot1x default group FABRIC",
              "aaa authorization network default group FABRIC",
              "! accounting: the sessions fabric lists and can disconnect",
              "aaa accounting update newinfo periodic 60",
              "aaa accounting dot1x default start-stop group FABRIC",
              "!",
              "! CoA and Disconnect from fabric (UDP " + str(port) + "; IOS-XE's own default is 1700)",
              "aaa server radius dynamic-author",
              " client " + host + " server-key " + SECRET_PLACEHOLDER,
              " port " + str(port),
              " auth-type any",
              "!",
              "radius-server attribute 6 on-for-login-auth",
              "radius-server attribute 8 include-in-access-req",
              "radius-server attribute 25 access-request include",
              "radius-server attribute 31 mac format ietf upper-case",
              "radius-server vsa send accounting",
              "radius-server vsa send authentication",
              "dot1x system-auth-control",
              "!",
              "! each access port (NOT the uplinks, access points, fabric's own port or the switch's management):",
              "interface range GigabitEthernet1/0/1 - 24",
              " switchport mode access",
              " authentication host-mode multi-auth",
              " authentication order dot1x mab",
              " authentication priority dot1x mab",
              " authentication port-control auto",
              " authentication periodic",
              " authentication timer reauthenticate server",
              " mab",
              " dot1x pae authenticator",
              " spanning-tree portfast",
              "end"]
    return "\n".join(lines) + "\n"
