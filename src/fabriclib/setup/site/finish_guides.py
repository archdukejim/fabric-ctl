"""The finish's illustrated steps and commands per operating system (manual 1.3.6.6). The commands are copies of the
manual's topics, 4.3.6.2 and 4.3.6.3, with <host_ip>, <domain> and <certs_url> filled in:
tests/setup/site/guides_test.py
compares them with the manual, so neither can drift (global 5.3)."""

TRUST = [
    {"os": "Windows", "picture": "trust-windows.svg", "alt": "Download root-ca.cer, install it, choose Trusted Root.",
     "steps": ["Open <certs_url> and download root-ca.cer.",
               "Compare the root's fingerprint on this page with the one shown there.",
               "In PowerShell as administrator, run the two commands below (or double-click the file: Install "
               "Certificate, Local Machine, Trusted Root Certification Authorities).",
               "Restart your browser, then reload this page: no warning proves the root is trusted."],
     "commands": ["Invoke-WebRequest <certs_url>root-ca.cer -OutFile $env:TEMP\\root-ca.cer",
                  "Import-Certificate -FilePath $env:TEMP\\root-ca.cer -CertStoreLocation Cert:\\LocalMachine\\Root"]},
    {"os": "macOS", "picture": "trust-macos.svg",
     "alt": "Download root-ca.crt, add it to the System keychain, trust it.",
     "steps": ["Open <certs_url> and compare the root's fingerprint on this page with the one shown there.",
               "In Terminal, run the two commands below (or open the file in Keychain Access, System, and set it to "
               "Always Trust).",
               "Restart your browser, then reload this page: no warning proves the root is trusted."],
     "commands": ["curl -sSo /tmp/root-ca.crt <certs_url>root-ca.crt",
                  "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "
                  "/tmp/root-ca.crt"]},
    {"os": "Ubuntu", "picture": "trust-ubuntu.svg",
     "alt": "Download root-ca.crt, add it to the system's store, update it.",
     "steps": ["Open <certs_url> and compare the root's fingerprint on this page with the one shown there. Firefox and "
               "Chrome keep their own stores: the install-all script on that page covers them too.",
               "In a terminal, run the two commands below.",
               "Restart your browser, then reload this page: no warning proves the root is trusted."],
     "commands": ["sudo wget -nv -O /usr/local/share/ca-certificates/fabric-root-ca.crt <certs_url>root-ca.crt",
                  "sudo update-ca-certificates"]},
]

DNS = [
    {"os": "Windows", "picture": "dns-windows.svg", "alt": "A rule sends names under your domain to fabric's DNS.",
     "steps": ["In PowerShell as administrator, run the commands below: names under <domain> go to fabric's DNS, and "
               "everything else stays as it is.",
               "The last one should answer with <host_ip>."],
     "commands": ['Add-DnsClientNrptRule -Namespace ".<domain>" -NameServers "<host_ip>"',
                  "Clear-DnsClientCache",
                  "Resolve-DnsName <console_name>"]},
    {"os": "macOS", "picture": "dns-macos.svg", "alt": "A resolver file sends names under your domain to fabric's DNS.",
     "steps": ["In Terminal, run the commands below: names under <domain> go to fabric's DNS, and everything else "
                "stays "
               "as it is.",
               "The last one should show <host_ip>."],
     "commands": ["sudo mkdir -p /etc/resolver",
                  'echo "nameserver <host_ip>" | sudo tee /etc/resolver/<domain>',
                  "sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder",
                  "dscacheutil -q host -a name <console_name>"]},
    {"os": "Ubuntu", "picture": "dns-ubuntu.svg",
     "alt": "systemd-resolved sends names under your domain to fabric's DNS.",
     "steps": ["In a terminal, run the commands below: names under <domain> go to fabric's DNS, and everything else "
               "stays as it is.",
               "The last one should answer with <host_ip>."],
     "commands": ["sudo mkdir -p /etc/systemd/resolved.conf.d",
                  "printf '[Resolve]\\nDNS=<host_ip>\\nDomains=~<domain>\\n' | "
                  "sudo tee /etc/systemd/resolved.conf.d/fabric.conf",
                  "sudo systemctl restart systemd-resolved",
                  "resolvectl query <console_name>"]},
]


def _filled(text, values):
    """Purpose: put the real values into one line.
    Inputs:  text — str; values — {placeholder: value}.
    Returns: str.
    Fails:   never.
    Feeds:   finish_guides."""
    for name, value in values.items():
        text = text.replace(f"<{name}>", value)
    return text


def finish_guides(host_ip, domain, certs_url, console_name):
    """Purpose: the finish's guides with the real address and domain filled in (manual 1.3.6.6).
    Inputs:  host_ip, domain, certs_url, console_name — str; each value checked when it was asked (a strict rule keeps
             out what could break a command, manual 1.1.5.7).
    Returns: (trust guides, DNS guides): lists of {os, picture, alt, steps, commands}.
    Fails:   never.
    Feeds:   setup/site/finish_data."""
    values = {"host_ip": host_ip, "domain": domain, "certs_url": certs_url, "console_name": console_name}
    return tuple([{**g, "steps": [_filled(s, values) for s in g["steps"]],
                   "commands": [_filled(c, values) for c in g["commands"]]} for g in guides] for guides in (TRUST, DNS))
