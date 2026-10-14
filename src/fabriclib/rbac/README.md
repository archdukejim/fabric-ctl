# fabriclib/rbac

Who may do what in fabric (design 2.1.6.1). Permissions are Keycloak realm roles
(`fabric:<area>:<action>`); bundles are composite roles granted to directory
groups. fabric-agent checks every web UI call against the signed-in person's
token; the web UI only hides what they cannot use.

| File | What |
|---|---|
| `permissions.py` | The permissions, the role-name prefix and the bundles (admin, auditor, network / equipment / PKI operator, helpdesk, site helpdesk); each permission's site helpdesk form (2.1.9.21) |
| `required_permission.py` | fabric-agent route → the permission it needs (unlisted routes are refused) |
| `user_permissions.py` | The fabric permissions in a verified token's `roles` claim |
| `holds_permission.py` | Whether a token's permissions grant a route's: fully, only as the site helpdesk (this site's own people, 2.1.9.21), or not |
