"""Access entries fabric keeps on AD objects (manual 1.6.3.6): an entry added once, compared parsed (Samba rewrites
SDDL text), and a principal's SID by name."""
import ldb
from samba.dcerpc import security
from samba.sd_utils import SDUtils

OBJECT_ACES = (security.SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT, security.SEC_ACE_TYPE_ACCESS_DENIED_OBJECT)


def sid_of(samdb, name):
    """Purpose: an account's or group's SID by its name.
    Inputs:  samdb — SamDB; name — sAMAccountName.
    Returns: str.
    Fails:   IndexError if it does not exist; ldb.LdbError from the search.
    Feeds:   ensure_directory_acl, protect_top_tier, admin_gpo, converge."""
    res = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                       expression=f"(sAMAccountName={ldb.binary_encode(name)})", attrs=["objectSid"])
    return str(samdb.schema_format_value("objectSid", res[0]["objectSid"][0]), "utf-8")


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
    Feeds:   ensure_directory_acl, protect_top_tier, admin_gpo."""
    domain_sid = security.dom_sid(samdb.get_domain_sid())
    utils, done = SDUtils(samdb), []
    for dn, ace in entries:
        want = security.descriptor.from_sddl("D:" + ace, domain_sid).dacl.aces[0]
        if not any(_same(have, want) for have in utils.read_sd_on_dn(dn).dacl.aces):
            utils.dacl_add_ace(dn, ace)
            done.append(f"{dn}: {ace}")
    return done
