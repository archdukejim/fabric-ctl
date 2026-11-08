import socket
import ssl

from fabriclib.common.dns_query import dns_query


def check_console(ctx, timeout=5.0, dns_port=53, https_port=443):
    """Purpose: the host's own half of the finish's check (manual 1.3.6.6): fabric's DNS answers the console's name with
             this host, and the console answers it with a certificate that verifies against fabric's root. The browser
             does the other half, from the person's computer. Certificates are verified (global Rule 10).
    Inputs:  ctx — SetupContext: vars hostname_mgr, host_ip; the published root under nginx/www/certs;
             timeout — seconds; dns_port, https_port — where they are (tests give their own).
    Returns: "" when both hold; otherwise what failed (str).
    Fails:   never: a failure is the answer.
    Feeds:   setup/site/guided_site."""
    v = ctx.vars
    name, ip = v.get("hostname_mgr"), v.get("host_ip")
    try:
        answers = dns_query(name, ip, port=dns_port, timeout=timeout)
    except Exception as e:
        return f"fabric's DNS at {ip} did not answer for {name}: {e}"
    if ip not in answers:
        return f"fabric's DNS at {ip} answers {name} with {', '.join(answers) or 'nothing'}, not {ip}"
    try:
        context = ssl.create_default_context(cafile=ctx.path("nginx", "www", "certs", "root-ca.crt"))
        with socket.create_connection((ip, https_port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=name):
                return ""
    except (OSError, ssl.SSLError) as e:
        return f"the console at {name} did not answer with fabric's certificate: {e}"
