"""Access entries fabric keeps on AD objects (manual 1.6.3.6): an entry added once, or removed, compared parsed (Samba
rewrites SDDL text), and a principal's SID by name."""
import ldb
from samba.dcerpc import security
from samba.sd_utils import SDUtils

OBJECT_ACES = (security.SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT, security.SEC_ACE_TYPE_ACCESS_DENIED_OBJECT)


def sid_of(samdb, name):
    """Purpose: an account's or group's SID by its name.
    Inputs:  samdb — SamDB; name — sAMAccountName.
    Returns: str.
    Fails:   IndexError if it does not exist; ldb.LdbError from the search.
    Feeds:   ensure_site_acl, admin_gpo, converge."""
    res = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                       expression=f"(sAMAccountName={ldb.binary_encode(name)})", attrs=["objectSid"])
    return str(samdb.schema_format_value("objectSid", res[0]["objectSid"][0]), "utf-8")


def schema_guid(samdb, name):
    """Purpose: an attribute's or class's schemaIDGUID (for fabric's own attributes, the one Samba chose when fabric's
             schema added it).
    Inputs:  samdb — SamDB; name — the lDAPDisplayName.
    Returns: str, the GUID.
    Fails:   IndexError when the schema has no such attribute (ensure_schema runs first); ldb.LdbError.
    Feeds:   ensure_site_acl, protect_privileged_people."""
    res = samdb.search(base=str(samdb.get_schema_basedn()), scope=ldb.SCOPE_ONELEVEL,
                       expression=f"(lDAPDisplayName={name})", attrs=["schemaIDGUID"])
    return str(samdb.schema_format_value("schemaIDGUID", res[0]["schemaIDGUID"][0]), "utf-8")


def owner_of(samdb, dn):
    """Purpose: an object's owner, from its security descriptor.
    Inputs:  samdb — SamDB; dn — str.
    Returns: str, the owner's SID.
    Fails:   ldb.LdbError reading the security descriptor (no such object).
    Feeds:   ensure_site_acl (_check_owners)."""
    return str(SDUtils(samdb).read_sd_on_dn(dn).owner_sid)


def _same(a, b):
    """Purpose: whether two parsed access entries grant the same thing to the same principal.
    Inputs:  a, b — security.ace.
    Returns: bool (an object entry's attribute or class counts).
    Fails:   never.
    Feeds:   ensure_aces."""
    if (a.type, a.flags, a.access_mask, str(a.trustee)) != (b.type, b.flags, b.access_mask, str(b.trustee)):
        return False
    return a.type not in OBJECT_ACES or str(a.object.type) == str(b.object.type)


def ensure_aces(samdb, entries):
    """Purpose: each access entry present on its object, added when missing.
    Inputs:  samdb — SamDB (as the system); entries — list of (dn str, SDDL entry str "(A;CI;…;;;S-…)").
    Returns: list of str, the entries added.
    Fails:   ldb.LdbError reading or changing a security descriptor; RuntimeError for invalid SDDL.
    Feeds:   ensure_site_acl, admin_gpo."""
    domain_sid = security.dom_sid(samdb.get_domain_sid())
    utils, done = SDUtils(samdb), []
    for dn, ace in entries:
        want = security.descriptor.from_sddl("D:" + ace, domain_sid).dacl.aces[0]
        if not any(_same(have, want) for have in utils.read_sd_on_dn(dn).dacl.aces):
            utils.dacl_add_ace(dn, ace)
            done.append(f"{dn}: {ace}")
    return done


def remove_aces(samdb, entries):
    """Purpose: each access entry gone from its object when it is there (an explicit entry fabric added and no longer
             wants: protect_privileged_people's denies on a person who no longer holds a role).
    Inputs:  samdb — SamDB (as the system); entries — list of (dn str, SDDL entry str).
    Returns: list of str, the entries removed.
    Fails:   ldb.LdbError reading or changing a security descriptor; RuntimeError for invalid SDDL.
    Feeds:   protect_privileged_people."""
    domain_sid = security.dom_sid(samdb.get_domain_sid())
    utils, done = SDUtils(samdb), []
    for dn, ace in entries:
        want = security.descriptor.from_sddl("D:" + ace, domain_sid).dacl.aces[0]
        sd = utils.read_sd_on_dn(dn)
        found = [have for have in sd.dacl.aces if _same(have, want)
                 and not have.flags & security.SEC_ACE_FLAG_INHERITED_ACE]
        if found:
            for have in found:
                sd.dacl_del_ace(have)
            utils.modify_sd_on_dn(dn, sd)
            done.append(f"{dn}: {ace} removed")
    return done
