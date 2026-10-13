from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns.common.landing_link import landing_link


def set_record_link(actor, key, rtype, index, expected_name, form, source="cli"):
    """Purpose: link a record of the site's zone from the landing page, or stop linking it (manual 1.4.2.4, 2.1.2.22
             item 4): the landing page's own section of the DNS tab, apart from the record form. The link is kept on
             the record (`link:`, 2.1.4.2), as before, so nothing migrates; the next apply renders the page.
    Inputs:  actor — str, who asks (audit); key — the zone key (only dynamic_zone_var: the landing page links the
             site's zone); rtype — "A", "AAAA" or "CNAME"; index — int position among that type's records;
             expected_name — the name the page showed; form — dict: link ("on" links it, anything else unlinks),
             link_label, link_port, link_path (common/landing_link); source — "cli" (default) or "web". Reads and
             writes vars.yaml under vars_lock.
    Returns: the record dict as saved (with "link" when linked).
    Fails:   ValidationError "the landing page links only the site's own zone", "only A, AAAA and CNAME records can
             be linked", "a wildcard name cannot be linked", "record changed since it was shown; reload and try
             again", or landing_link's; OSError or yaml.YAMLError from the vars file or the audit log.
    Feeds:   agent route POST /v1/zones/<key>/records/link (fabric-agent, dns:write)."""
    if key != "dynamic_zone_var":
        raise ValidationError("the landing page links only the site's own zone")
    if rtype not in ("A", "AAAA", "CNAME"):
        raise ValidationError("only A, AAAA and CNAME records can be linked")
    if "*" in str(expected_name):
        raise ValidationError("a wildcard name cannot be linked")
    link = landing_link(form)
    with vars_lock():
        data = load_vars()
        records = ((data.get("dns") or {}).get(key) or {}).get(rtype) or []
        if not 0 <= index < len(records) or (records[index].get("name") or "") != expected_name:
            raise ValidationError("record changed since it was shown; reload and try again")
        record = records[index]
        if link:
            record["link"] = link
        else:
            record.pop("link", None)
        save_vars(data)
    write_audit(actor, "DNS_LINK" if link else "DNS_UNLINK", f"zone={key} {rtype} {expected_name} {link or ''}".strip(),
                source)
    return record
