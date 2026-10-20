"""The settings a 0.7.x settings file holds that 0.8.0 no longer takes (decision 2.1.1.60, manual 3.3.5.3).

`fabricctl setup --file` lists each one it finds, with why, and ignores it (setup/drop_retired_settings); it never
refuses a file for one. This is the one list: the manual cites it, it does not copy it.
"""

# key -> why 0.8.0 no longer takes it (shown beside the key)
RETIRED_SETTINGS = {
    "dc_name": "fabric names its domain controllers itself (2.1.6.65): the new domain's first DC is dc-0001",
    "posix_id_start": "a DC's number gives its id range (2.1.6.63, 2.1.6.86)",
    "posix_id_block": "a DC's number gives its id range (2.1.6.63, 2.1.6.86)",
    "posix_id_range": "a DC's number gives its id range (2.1.6.63, 2.1.6.86)",
    "logon_policies": "who signs in where is given by grants (2.1.6.73, 1.6.13)",
    "ad_site_ou": "there are no site OUs: sites are groups (2.1.6.72)",
    "ad_org_ou": "there are no site OUs: sites are groups (2.1.6.72)",
    "webui_admin_group": "the Directory Administrators' group is directory-admins (2.1.6.81)",
    "webui_admin_name": "the first administrator's names are webui_admin_first_name and webui_admin_last_name "
                        "(2.1.6.93)",
    "image_pins": "it names images of the old release: 0.8.0 runs its own release's images",
    "image_rolled_back": "it names images of the old release: 0.8.0 runs its own release's images",
}

# keys only a 0.7.x file holds (every 0.7.x vars.yaml has them): a file with one is a 0.7.x file, whose OLD_FILE_ONLY
# keys are ignored too; in a newer file they are still 0.8.0 settings (a file naming the DC is refused, 2.1.6.65;
# image_pins and image_rolled_back hold an install's own images)
OLD_FILE_MARKS = ("posix_id_start", "posix_id_block", "posix_id_range", "logon_policies", "ad_site_ou", "ad_org_ou",
                  "webui_admin_group")
OLD_FILE_ONLY = ("dc_name", "image_pins", "image_rolled_back")

# 0.7.x's own directory groups, as its vars.yaml lists them (0.7.x's templates/vars.yaml.j2): an entry of a file's
# ldap_groups exactly like one of these is the old release's, not the admin's, and is ignored (0.8.0 has its own,
# 2.1.6.81: `admins` is directory-admins, with the same gid)
OLD_DEFAULT_GROUPS = (
    {"gidNumber": 1040001, "name": "admins", "permissions": ["read", "write", "modify"]},
    {"gidNumber": 1040002, "name": "auditors", "bundle": "fabric-auditor"},
    {"gidNumber": 1040003, "name": "network-operators", "bundle": "fabric-network-operator"},
    {"gidNumber": 1040004, "name": "equipment-operators", "bundle": "fabric-equipment-operator"},
    {"gidNumber": 1040005, "name": "pki-operators", "bundle": "fabric-pki-operator"},
    {"gidNumber": 1040006, "name": "helpdesk", "bundle": "fabric-helpdesk"},
    {"gidNumber": 1040007, "name": "network-staff",
     "description": "May join the network by password (802.1X EAP-TTLS)"},
    {"gidNumber": 1040008, "name": "network-guests",
     "description": "May join the network by password (802.1X EAP-TTLS) — map it to a guest VLAN"},
    {"gidNumber": 1040009, "name": "users", "permissions": ["read"]},
)
