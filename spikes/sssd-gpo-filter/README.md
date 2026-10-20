# Spike: does sssd honour a GPO's security filtering? (for 1.6.13.4)

Throwaway (global Rule 4's exception): branch `spike/sssd-gpo-filter` only, never merged into `src/`. The outcome
goes into the manual's notes, written by the owner.

```bash
sudo python3 spikes/sssd-gpo-filter/spike.py        # SPIKE_KEEP=1 leaves the containers for a look
```

`spike.py` starts a real Samba AD DC (`tests/samba/start_dc.py`), joins a real Ubuntu 24.04 member with fabric's
`join-linux.sh` (as `tests/samba/linux_join.py` does, with its `systemctl` shim), and runs the cases. `dc_gpo.py`
runs inside the DC: fabric's own `ensure_gpo` makes each GPO (a `GptTmpl.inf` setting
`SeRemoteInteractiveLogonRight`), then the security filtering is set as GPMC sets it: Authenticated Users keep Read,
only the filtering group gets Read + Apply Group Policy (`edacfd8f-...`); SYSVOL's ACL is reset with `set_gpo_acl`.
The check is PAM's account phase (`pamtester sshd|login <user> acct_mgmt`), where `ad_gpo_access_control` runs.

## Run 2026-10-20

- sssd 2.9.4 (`sssd-ad 2.9.4-1.1ubuntu6.8`, Ubuntu 24.04.5 LTS); Samba 4.22.11 (Debian 13 image `fabric/samba:test`).
- sssd.conf exactly as the join writes it (`access_provider = ad`, `ad_gpo_access_control = enforcing`, no
  `ad_gpo_cache_timeout`: the default 5 s), plus `debug_level = 6`. Machine `GPOFWS$` in OU=servers,OU=machines; all
  GPOs linked at OU=machines; G1, G2 (holding the machine), G3 (not), UG1 (holding user gu1 only).
- At OU=machines before the spike: only `fabric: lan Windows baseline`, which sets no log-on right.

| Case | Setup | gu1 sshd | gu2 sshd |
|---|---|---|---|
| baseline | no spike GPO | allow | allow (login too) |
| 4 | GPO remote -> gu1, filtered to G3 (machine not in it) | allow | allow: ignored |
| control | same GPO, unfiltered | allow | deny |
| 1 | GPO remote -> gu1, filtered to G1 (machine in it) | allow | **deny** (login: both allow, that right not set) |
| 3a | + GPO remote -> gu2, filtered to G2, last in `gPLink` | **deny** | allow |
| 3b | same two, link order swapped (G1's last in `gPLink`) | allow | **deny** |
| 5 | GPO remote -> gu2, filtered to UG1 (a people group with gu1; machine not in it) | **deny** | allow |
| 2 | case 1, machine removed from G1 | allow | allow, at the very next check (< 1 s) |
| 2r | machine added back to G1 | allow | deny, at the very next check (< 1 s) |

sssd's log (case 1 state): `ad_gpo_connect_done ... sam_account_name is GPOFWS$`, the host's `tokenGroups` fetched
(`Processing membership SID ...-1128`, `-1129`: G1, G2), `ad_gpo_filter_gpos_by_dacl ... GPO applicable to target per
security filtering`, then `RESULTANT POLICY: Remote Interactive, allowed_sids = [gu1, S-1-5-32-544]`; for gu2
`GPO access check failed ... Host Access Denied`. GPO files are re-downloaded only when the GPT version changes
(`retrieving GPO from cache ... cached_gpt_version`).

## Findings

1. **Security filtering by a computer group is honoured** (cases 1, 4, control): the GPO applies only when the
   machine is in the group granted Apply Group Policy.
2. **Removal from the group: the GPO stops applying, and with no other GPO setting the right, sssd allows everyone**
   (default allow when no applicable GPO sets the right).
3. **No merging:** with two applicable GPOs setting the same right, the whole right comes from one GPO, the one
   **last in the OU's `gPLink` string** (Windows' link order 1, highest precedence); swapping the order swaps who gets
   in. Same as Windows.
4. **Membership changes take effect at the next access check**: sssd looks up the host account and its
   `tokenGroups` online on every check (the GPO list and DACLs too); `ad_gpo_cache_timeout` only caches the GPO files
   and is not what bounds it. No refresh interval applies while the DC is reachable.
5. **sssd also matches the signing-in user's own SIDs and groups** against the filter (case 5): a GPO filtered to a
   group that holds a person applies when that person signs in, anywhere the GPO is linked. Windows evaluates machine
   policy against the computer only. So the computed `access-<n>` groups must hold computers only.
