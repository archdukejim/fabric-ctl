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

## Follow-up 2026-10-20: why sssd 2.8 (Debian 12) drops a GPO filtered to a computer group (2.3.6.19.6)

```bash
sudo python3 spikes/sssd-gpo-filter/spike28.py      # names spike28-*; its own image tag spike28/samba:test
```

Same DC; two members joined with `join-linux.sh --unmanaged`: Debian 12 (`sssd-ad 2.8.2-4+deb12u1`, the newest in
bookworm, no backport) and Debian 13 (`sssd-ad 2.10.1-2+b1`, the control); both in computer group G1. One GPO giving
`SeRemoteInteractiveLogonRight` to gu1, linked at OU=machines; only its DACL changes per case. Applied = gu2 refused
over SSH (`pamtester sshd gu2 acct_mgmt`). Run twice, same results.

| Case | DACL (besides Samba's defaults) | Debian 12 (2.8.2) | Debian 13 (2.10.1) |
|---|---|---|---|
| control | AU Read + Apply | applied | applied |
| A (fabric's `set_gpo_filter`) | AU Read; G1 Read + Apply (`OA` ACE, `edacfd8f-...`) | **not applied** | applied |
| a | A + each machine's own SID Read + Apply | applied | applied |
| a2 | AU Read; each machine's SID Apply only (no group) | applied | applied |
| a3 | AU Read; only SD12$'s SID Apply | applied | not applied (not named) |
| b1 | AU Read; G1 plain allow `(A;CI;RPLCLORCCR;;;G1)` | not applied | not applied |
| b2 | A without the CI flag | not applied | applied |
| b3 | AU Read; machines' SIDs plain allow with CR | not applied | not applied |
| b4 | AU Read; machines' SIDs `OA` with CR and no object type | applied | applied |
| c1 | no AU entry; G1 Read + Apply | not applied | applied |
| c2 | no AU entry; machines' SIDs Read + Apply | applied | applied |
| d | AU Read; UG1 (a group of people holding gu2) Read + Apply | applied for gu2 | applied for gu2 |
| e | A, Debian 12 with `ad_gpo_ignore_unreadable = True` | not applied | applied |
| f | SD12$ taken out of G1, its SID entry left | applied (stale entry) | applied |
| f2 | SD12$ out of G1, its SID entry removed | not applied | applied |

sssd's log (debug 9, `--logger=files`; Debian's default logger is journald, absent in the container), case A: on
2.8.2 the access request looks up only the user's groups (`Processing membership` -1121, -1129, 513), then
`ad_gpo_evaluate_dacl ... GPO apply group policy access denied (security)` and `GPO not applicable ... result of
DACL evaluation` for the spike GPO. On 2.10.1 the same request also fetches the host's `tokenGroups` (-1118, -1128 =
G1, -515) and applies it.

Cause, in the source: sssd 2.8.2's `ad_gpo_ace_includes_client_sid()` (`src/providers/ad/ad_gpo.c`) matches an ACE
against the signing-in user's SID, the host's own `objectSid` (`host_sid`, read by `ad_gpo_get_host_sid_retrieval_done`)
and the user's groups from `ad_gpo_get_sids()` (sysdb initgroups of the user) plus Authenticated Users, never the
host's groups. Upstream fixed it in "ad: gpo evalute host groups" (c02e09af, SSSD issue #5708; in 2.10.0, backported
to 2.9.4 as 09dcc73e): `ad_gpo_filter_gpos_by_dacl()` calls `ad_gpo_get_sids()` for the host too and matches
`host_group_sids`. Debian 12 carries neither (its only update is CVE-2023-3758). No sssd.conf option changes it (2.8.2's
GPO options: access_control, implicit_deny, ignore_unreadable, cache_timeout, the map_* lists, default_right).
2.8.2 also treats only object ACEs (`OA`) as granting Apply; a plain allow with CR is neutral (b1, b3; 2.10 the same).

### Findings

1. sssd < 2.9.4 ignores the computer's groups in security filtering; it does honour the computer's own SID.
2. **A fix fabric can apply without weakening security:** besides `access-<n>`'s entries, each GPO gets one
   `(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;<machine SID>)` per machine in `access-<n>` (AU keeps Read; the
   machine needs no Read entry, a2), compiled from the group's membership and removed when a machine leaves (f, f2).
   It names exactly the machines the group holds, so it applies to nothing more; Windows and sssd ≥ 2.9.4 treat the
   machine's own SID as theirs too. The cost: a membership change reaches a 2.8 machine only at the next compile
   (the 5-minute timer), not at the next sign-in, and the DACL grows by one entry per machine.
3. Removing AU's Read does not help (c1); the ACE's inheritance flag and form do not matter beyond "object ACE" (b2, b4).
4. Otherwise sssd ≥ 2.9.4 is the requirement: Debian 12 ships 2.8.2 with no backport.
