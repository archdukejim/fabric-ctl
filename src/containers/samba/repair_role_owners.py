import ldb


def repair_role_owners(samdb):
    """Purpose: the roles this DC holds named by its NTDS object's current DN (manual 1.6.5.15). Renaming the AD site
             moves the DC (ensure_ad_site), but each role object's fSMORoleOwner keeps the old DN's text beside the
             right GUID, and Samba checks "we are master" by that text: the schema master refuses every schema
             addition until it is rewritten (2.3.1.19.1).
    Inputs:  samdb — SamDB, opened locally as the system.
    Returns: list of str, one line per role owner rewritten.
    Fails:   ldb.LdbError for a change AD refuses.
    Feeds:   converge (before the schema, and again after the AD site)."""
    ntds = samdb.get_dsServiceName()
    guid = samdb.schema_format_value("objectGUID", samdb.search(base=ntds, scope=ldb.SCOPE_BASE,
                                                                 attrs=["objectGUID"])[0]["objectGUID"][0])
    want = str(ntds).lower()
    done = []
    for nc in samdb.search(base="", scope=ldb.SCOPE_BASE, attrs=["namingContexts"])[0]["namingContexts"]:
        for m in samdb.search(base=str(nc), scope=ldb.SCOPE_SUBTREE, expression="(fSMORoleOwner=*)",
                              attrs=["fSMORoleOwner"], controls=["reveal_internals:0", "extended_dn:1:1",
                                                                 "search_options:1:2"]):
            stored = ldb.Dn(samdb, str(m["fSMORoleOwner"][0]))
            owner = stored.get_extended_component("GUID")
            if owner is None or samdb.schema_format_value("objectGUID", owner) != guid:
                continue                    # a role another DC holds: its own to keep
            if str(stored).lower() == want:
                continue
            samdb.modify(ldb.Message.from_dict(samdb, {"dn": str(m.dn), "fSMORoleOwner": str(ntds)},
                                               ldb.FLAG_MOD_REPLACE))
            done.append(f"role owner of {m.dn} renamed {ntds}")
    return done
