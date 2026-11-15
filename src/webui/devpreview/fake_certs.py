def fake_certs(state):
    """Purpose: PKI's Issued list as the agent's certs_overview answers it (2.1.5.13): the sample ledger (a device's
             certificate as an 802.1X machine's), fabric's own service certificates and an ACME one.
    Inputs:  state — DevState (issued, certs_other).
    Returns: {"certs", "stepca_error", "service_error", "directory_error", "sources"}.
    Fails:   never.
    Feeds:   fake_reads (GET /v1/pki/certs), fake_misc (lookup, revoke)."""
    d = state.data
    rows = [{**c, "source": "8021x" if c.get("device") else "here", "cn": c["subject"].split("CN=")[-1],
             "device_roles": ["laptops"] if c.get("device") else [], "how": "key + certificate (PKCS#12)"
             if c.get("device") else "", "revocable": c["status"] in ("valid", "expires soon")} for c in d["issued"]]
    rows += [{**c, "revocable": c["status"] in ("valid", "expires soon")} for c in d["certs_other"]]
    return {"certs": rows, "stepca_error": "", "service_error": "", "directory_error": "",
            "sources": {"here": "Issued here", "fabric": "fabric's own", "acme": "Over ACME",
                        "8021x": "802.1X machines", "stepca": "Other Step-CA"}}
