"""Access entries fabric keeps on AD objects (manual 1.6.3.6): an entry added once, compared parsed (Samba rewrites
SDDL text), and a principal's SID by name."""
import ldb
from samba.dcerpc import security
from samba.sd_utils import SDUtils

OBJECT_ACES = (security.SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT, security.SEC_ACE_TYPE_ACCESS_DENIED_OBJECT)
# the LDAP control that reads or writes a security descriptor's DACL alone (SECINFO_DACL)
DACL_ONLY = "sd_flags:1:4"


def sid_of(samdb, name):
    """Purpose: an account's or group's SID by its name.
    Inputs:  samdb — SamDB; name — sAMAccountName.
    Returns: str.
    Fails:   IndexError if it does not exist; ldb.LdbError from the search.
    Feeds:   ensure_directory_acl, protect_top_tier, admin_gpo, converge, ensure_ou_rights."""
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


def ensure_aces(samdb, entries, dacl_only=False, gone_ok=False):
    """Purpose: each access entry present on its object, added when missing.
    Inputs:  samdb — SamDB (as the system); entries — list of (dn str, SDDL entry str "(A;CI;…;;;S-…)"); dacl_only —
             read and write the DACL alone (an account that is not the system, such as an OU's owner: the whole
             descriptor holds the SACL, which only the system reads); gone_ok — True for entries on objects a search
             just found (accounts, not fabric's folders): one deleted since that search is skipped, not an error
             (a site's join account its new DC deletes while the root converges: the samba suite on arm64, 2.3.6.29).
    Returns: list of str, the entries added.
    Fails:   ldb.LdbError reading or changing a security descriptor (a missing object too, unless gone_ok);
             RuntimeError for invalid SDDL.
    Feeds:   ensure_directory_acl, protect_top_tier, admin_gpo, ensure_ou_rights."""
    domain_sid = security.dom_sid(samdb.get_domain_sid())
    utils, done = SDUtils(samdb), []
    for dn, ace in entries:
        want = security.descriptor.from_sddl("D:" + ace, domain_sid).dacl.aces[0]
        try:
            added = _ensure_one(utils, dn, ace, want, dacl_only)
        except ldb.LdbError as e:
            if gone_ok and e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                continue
            raise
        if added:
            done.append(f"{dn}: {ace}")
    return done


def _ensure_one(utils, dn, ace, want, dacl_only):
    """Purpose: one access entry on one object, added when missing.
    Inputs:  utils — SDUtils; dn — str; ace — SDDL entry str; want — the entry parsed; dacl_only — as ensure_aces.
    Returns: True when it was added.
    Fails:   ldb.LdbError reading or changing the security descriptor.
    Feeds:   ensure_aces."""
    if dacl_only:
        sd = utils.read_sd_on_dn(dn, controls=[DACL_ONLY])
        if any(_same(have, want) for have in sd.dacl.aces):
            return False
        sd.dacl_add(want)
        utils.modify_sd_on_dn(dn, sd, controls=[DACL_ONLY])
        return True
    if any(_same(have, want) for have in utils.read_sd_on_dn(dn).dacl.aces):
        return False
    utils.dacl_add_ace(dn, ace)
    return True
