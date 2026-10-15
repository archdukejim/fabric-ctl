from fabriclib.pki.common.ca_files import ca_files
from fabriclib.pki.common.describe_cert import describe_cert
from fabriclib.pki.common.to_pem import to_pem
from fabriclib.pki.common.valid_days import DEFAULT_MAX_DAYS


def ca_summary(v):
    """Purpose: Summarise the fabric CA for the PKI page: root and intermediate details, where devices
             download them, and the validity cap for hand-issued certificates.
    Inputs:  v — fabric vars: deploy_base_dir (CA files via ca_files), domain, hostname_stepca,
             pki_manual_max_days (default DEFAULT_MAX_DAYS, 1825). Reads root_ca.crt and intermediate_ca.crt.
    Returns: {"domain", "certs_url": "http://<hostname_stepca>/certs/" (1.5.1.6), "max_days": int,
             "root": describe_cert dict, "intermediate": describe_cert dict (first certificate of the file)}.
    Fails:   OSError if a CA file is missing or unreadable; ValueError if pki_manual_max_days is not a
             number; ValidationError from to_pem / describe_cert (openssl) if a file holds no certificate.
    Feeds:   agent route GET /v1/pki/ca (agent/ (fabric-agent) Handler.dispatch) -> webui agentclient.ca_summary
             -> the PKI page.
    """
    out = {"domain": v.get("domain", ""), "certs_url": f"http://{v.get('hostname_stepca', '')}/certs/",
           "max_days": int(v.get("pki_manual_max_days")
                                                                                 or DEFAULT_MAX_DAYS)}
    for label, path in zip(("root", "intermediate"), ca_files(v)):
        with open(path) as f:
            out[label] = describe_cert(to_pem(f.read(), "cert")[0])
    return out
