from fabriclib.access.check_access import check_access
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.write_audit import write_audit
from fabriclib.deploy.deploy_paths import deploy_paths
from fabriclib.dns.publish_plan_records import publish_plan_records
from fabriclib.common.try_vars_lock import try_vars_lock
from fabriclib.ipam.poll_plan import poll_plan
from fabriclib.secrets.load_secrets import load_secrets


class _Held:
    """The settings' lock Sync now already holds, handed to the poll so it does not try to take it a second time."""

    def close(self):
        """Purpose: nothing: Sync now releases the real lock itself.
        Inputs:  none.
        Returns: None.
        Fails:   never.
        Feeds:   poll_plan (its finally)."""
        return None


def sync_plan(v, actor, source="cli", container="samba", secrets=None, poll=poll_plan, publish=publish_plan_records,
              take_lock=try_vars_lock, settings=None, caller=None, check=check_access):
    """Purpose: Sync now (decision 2.1.10.29, manual 1.10.4.28): on demand, the plan poll at once whatever the DC's USN
             says (Kea re-rendered and restarted when its input changed, the firewall brought in line when the served
             subnets changed) and, when DNS is affected, BIND's records published by the quick path
             (dns/publish_plan_records). Never a full apply; no service restarted but Kea. Refused while an apply holds
             the settings' lock. Audited (IPAM_SYNC), also when the DNS step fails. A signed-in person (the
             console) needs the grants' `networks:plan` at this site first (fabric-agent's check_access,
             1.10.4.35); root, from the CLI, acts for the Enterprise Admin.
    Inputs:  v — fabric vars (install_kea, site_name); actor — who asks (audit); source — "cli" or "web"; container —
             the DC's container; secrets — fabric's secrets (default load_secrets()); poll, publish, take_lock —
             poll_plan, publish_plan_records and the settings' lock taken without waiting (tests give their own);
             settings — function() -> vars.yaml as kept (default: load_vars of the deployed settings); caller —
             the signed-in person's user name, or None (root); check — check_access (tests give their own).
    Returns: {"state" (the poll's: "same plan", "rendered", …), "kea_restarted" (bool), "firewall" (bool),
             "dns_pending" (bool: what the poll found), "dns" (publish_plan_records' result, or None when DNS was
             current)}.
    Fails:   ValidationError, changing nothing: check_access's refusal (a person without `networks:plan` here),
             Kea not installed here, the subnets still in the settings (not
             upgraded), an apply holding the settings' lock. Then what the poll raises (the DC, OpenBao, Kea's check,
             the firewall), and the DNS step's refusal, said with what was done ("Kea is in line with the plan; BIND's
             records were not published: …"); OSError from the audit log.
    Feeds:   ipam/run_ipam_command (`fabricctl ipam sync`); agent/post_ipam_sync (POST /v1/ipam/sync, the Networks
             tab's Sync now)."""
    if caller is not None:
        check(v, caller, "networks:plan", {"site": v.get("site_name", "")}, container)
    if not v.get("install_kea"):
        raise ValidationError("DHCP is off at this site: there is no plan served here to sync")
    kept = (settings or (lambda: load_vars(deploy_paths()["vars"])))()
    if "subnets" in (kept.get("dhcp") or {}):
        raise ValidationError("this site's subnets are still in its settings, not in the address plan: an apply serves "
                              "them (sudo fabricctl --apply), and moves them into the plan")
    lock = take_lock()
    if lock is None:
        raise ValidationError("an apply is running (it holds the settings' lock) and reads the plan itself: sync again "
                              "when it ends")
    site = v.get("site_name", "")
    dns, error = None, None
    try:
        secrets = secrets if secrets is not None else load_secrets()
        out = poll(v, container=container, secrets=secrets, force=True, take_lock=_Held)
        if out.get("dns_pending"):
            try:
                dns = publish(secrets)
            except ValidationError as e:
                error = e
    finally:
        lock.close()
    dns_text = "dns=failed" if error else f"zones={','.join(dns['zones']) or '-'}" if dns else "dns=current"
    write_audit(actor, "IPAM_SYNC", f"site={site} state={out.get('state')} "
                f"kea_restarted={bool(out.get('kea_restarted'))} firewall={bool(out.get('firewall'))} "
                f"dns_pending={bool(out.get('dns_pending'))} {dns_text}", source)
    if error:
        raise ValidationError(f"Kea is in line with the plan{'' if not out.get('kea_restarted') else ' (updated)'}; "
                              f"BIND's records were not published: {error}. Sync again once it is fixed, or apply "
                              "(sudo fabricctl --apply)")
    return {"state": out.get("state"), "kea_restarted": bool(out.get("kea_restarted")),
            "firewall": bool(out.get("firewall")), "dns_pending": bool(out.get("dns_pending")), "dns": dns,
            **({"why": out["why"]} if out.get("why") else {})}
