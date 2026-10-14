import ldb


def schema_guid(samdb, name):
    """Purpose: an attribute's or a class's schemaIDGUID as an access entry names it (the object type of an object
             entry: which attribute may be written, which class created).
    Inputs:  samdb — SamDB; name — the attribute's or class's lDAPDisplayName.
    Returns: str, the GUID in its text form.
    Fails:   IndexError when the schema has no such name (ensure_schema adds fabric's first); ldb.LdbError.
    Feeds:   ensure_org_options (the editors' attributes), ensure_site_acl (a machine's SSH host keys, 2.1.7.13; the
             site helpdesk's attributes and the role groups' members, 2.1.9.21; the local-scan setting and the scan
             request, 2.1.10.30), protect_privileged_people (2.1.9.21)."""
    res = samdb.search(base=str(samdb.get_schema_basedn()), scope=ldb.SCOPE_ONELEVEL,
                       expression=f"(lDAPDisplayName={ldb.binary_encode(name)})", attrs=["schemaIDGUID"])
    return str(samdb.schema_format_value("schemaIDGUID", res[0]["schemaIDGUID"][0]), "utf-8")
