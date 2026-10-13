# fabriclib/radius/nas

The RADIUS clients' vendors (manual 1.11.1.2, decision 2.1.11.4): one table of facts per vendor, and what is made from
it.

| File | What |
|---|---|
| `profiles.py` | The vendor profiles (UniFi, Cisco, generic): VLAN attributes, MAB's shape, RadSec, CoA actions and port, why not, the setup page; RadSec's constants |
| `nas_profile.py` | One vendor's profile; an unknown vendor is refused |
| `policy_clients.py` | What FreeRADIUS's policy gets per client in `fabric-radius.json`: its vendor's MAB rules and VLAN attributes |
| `cisco_snippet.py` | The IOS-XE configuration for a Cisco client, filled in for this install, never holding the secret |
