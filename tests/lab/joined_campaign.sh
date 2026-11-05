#!/bin/bash
# -----------------------------------------------------------------------
# The lab's joined campaign (manual 3.1.5.11, decision 2.1.1.48): machines joined to fabric's domain checked through
# everything fabric does to itself. From Git Bash on gaming-23, after `start_lab.ps1 -Campaign joined` (rtr-1, ub24-1,
# ub26-2, ws25-1, each from its `clean` checkpoint). No Python runs here (Windows' python is a store stub): every check
# runs on the lab VMs over SSH with the lab key.
#
#   FROM_DEB=<fabricctl 0.8.0 .deb> TO_DEB=<the branch's .deb> tests/lab/joined_campaign.sh
#   [ONLY="join upgrade place images restart restore move rename fresh" picks steps; all by default, each needs those before it]
#
# The steps, each followed by client_check (the fabric host's own join, the Linux member ub26-2, the Windows member
# ws25-1: the machine's password still the DC's, a Kerberos ticket as the machine, a domain person resolved, the DC
# found through fabric's DNS, no failed sssd unit):
#   join     fabric at the floor (FROM_DEB, 0.8.0 until 1.0: 2.1.1.61) with tests/lab/joined_vars.yaml; ub26-2 and
#            ws25-1 joined with one-time passwords, piped from add-machine's output to the member (never an argument)
#   upgrade  TO_DEB installed over it, then setup unattended, as an operator upgrades
#   fresh    last: ub26-2 joined again, by this build's own steps as the certificates page gives them (4.6.6.2, 2.1.1.85)
#   move     ub26-2's floor script refreshed first (4.6.6.12, 2.1.1.84), with its refusals, then 4.2.4.2
#   place    ub26-2 and ws25-1 moved into an admin's OU at the domain's root (1.8.8.5, 2.1.6.106; 2.3.8.6: anywhere):
#            the person's access check, sudo, Windows' fabric GPOs and local Administrators the
#            same as before the move; the later steps then run with them there
#   images   every image updated and rolled back: tests/images/update.sh --ssh (2.1.14.12)
#   restart  fabricctl stop and start, then the fabric VM rebooted
#   restore  uninstall --export, then restore from it (3.2.4)
#   move     the fabric VM moved from 10.88.0.10 to 10.88.0.13 by 4.2.4.2: netplan, host_ip applied, the member
#            step (no clean-up by hand since 0.9.1: the apply does it, 2.1.1.74), the members' DNS moved, 4.2.4.7
#   rename   the fabric VM renamed by 4.2.4.3: the old way refused (2.1.6.104), `fabricctl admin rename-host`, the
#            apply, the member step (no clean-up by hand since 0.9.1), 4.2.4.7 (the DC keeps dc_name, 1.6.5.23; the
#            keytab holds the new name; local-admin follows it, 1.7.1.4.11)
# Afterwards the four VMs go back to `clean` (3.1.5.11 step 9).
# -----------------------------------------------------------------------
set -uo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
FABRIC=10.88.0.10; FIRST=$FABRIC; MOVED=10.88.0.13; LINUX=10.88.0.21; WIN=10.88.0.41
DOMAIN=lab.test; AD=ad.lab.test; PERSON=lab.admin; RENAMED=g23-vm-ub24-1b
ONLY="${ONLY:-join upgrade place images restart restore move rename fresh}"
# keepalives: a session whose address went away (the move) ends in about a minute instead of waiting for ever
SSH=(-i "$HOME/.ssh/g23_lab" -o "UserKnownHostsFile=$HOME/fabric-lab/known_hosts" -o BatchMode=yes -o ConnectTimeout=20
     -o ServerAliveInterval=15 -o ServerAliveCountMax=4)
PASS=0; FAIL=0
check() { if (set +o pipefail; eval "$2"); then echo "PASS $1"; PASS=$((PASS+1)); else echo "FAIL $1"; FAIL=$((FAIL+1)); return 1; fi; }
FLOOR="not run (no join step)"
# Purpose: end the campaign where a step it depends on did not happen; nothing after it runs on a half-built lab.
stop() { echo "STOP $1: the campaign ends here ($PASS passed, $FAIL failed)"; echo "FLOOR first setup: $FLOOR"; exit 1; }
wants() { case " $ONLY " in *" $1 "*) return 0 ;; esac; return 1; }
# Purpose: a command on a lab VM: its output without OpenSSH's notices, and the command's own exit status. The fabric
#          VM keeps its host key under its first address when it moves (HostKeyAlias): the constant FIRST, never
#          $FABRIC, which the move changes (run 6, 2026-11-01: the alias became the new address, refused).
on() {
    local out rc t0 alias
    alias=$([ "$1" = "$MOVED" ] && echo "$FIRST" || echo "$1")
    t0=$SECONDS
    out=$(ssh "${SSH[@]}" -o "HostKeyAlias=$alias" "labadmin@$1" "$2" 2>&1)
    rc=$?
    # a member whose DNS server is gone (the move, before 4.2.4.2 step 5) was slow to send its SSH banner (run 6):
    # said, with the time it took, and tried once more with longer to connect
    if [ $rc -eq 255 ] && printf '%s' "$out" | grep -q "banner exchange"; then
        echo "INFO $1: no SSH banner within 20 s (after $((SECONDS - t0)) s); once more, 90 s to connect"
        t0=$SECONDS
        out=$(ssh -o ConnectTimeout=90 "${SSH[@]}" -o "HostKeyAlias=$alias" "labadmin@$1" "$2" 2>&1)
        rc=$?
        echo "INFO $1: the second try ended with $rc after $((SECONDS - t0)) s"
    fi
    printf '%s\n' "$out" | grep -v "post-quantum\|store now\|upgraded. See\|^$" || true
    return $rc
}
F() { on "$FABRIC" "sudo bash -lc $(printf '%q' "$1")"; }          # as root on the fabric VM (wherever it is now)
L() { on "$LINUX" "sudo bash -lc $(printf '%q' "$1")"; }           # as root on the Linux member
W() { on "$WIN" "powershell -NoProfile -Command \"$1\""; }           # on the Windows member (labadmin: an admin)
win_dns() { W '(Get-DnsClientServerAddress -InterfaceAlias Ethernet -AddressFamily IPv4).ServerAddresses' | tr -d '\r' | tr '\n' ' ' | sed 's/ $//'; }
up() { local i; for i in $(seq 1 60); do on "$1" true >/dev/null 2>&1 && return 0; sleep 10; done; return 1; }
# a captured name is used only when it is a DNS name (letters, digits, dots, hyphens), never as text to run
dc_fqdn() { F "awk '/^hostname_dc:/ {print \$2}' /opt/fabric/config/vars.yaml" | grep -E '^[A-Za-z0-9.-]+$' || true; }

# Purpose: one joined Linux machine's check, as root on it: its join, a machine ticket, a person, the DC by name. The
#          machine's account is read from its keytab, so a renamed host is checked under the account it joined as.
linux_ok() {   # $1 label, $2 F or L
    local dc acct; dc=$(dc_fqdn)
    acct=$($2 "klist -k /etc/krb5.keytab | awk '/\\\$@/ {print \$2; exit}'")
    [[ "$acct" =~ ^[A-Za-z0-9._-]+\$@[A-Za-z0-9.-]+$ ]] || acct=""   # only a principal NAME$@REALM, never other text
    local q=${acct//\$/\\\$}       # NAME$@REALM: its $ kept from the remote shell (an unescaped "$@" expanded to nothing)
    # adcli is on a machine the join script joined; setup gives the fabric host none unless its password is renewed
    # (1.6.11.12), and there the machine ticket below is the proof that its key is the DC's
    if $2 'command -v adcli' >/dev/null 2>&1; then
        check "$1: adcli testjoin (the machine's password is the DC's)" "$2 'adcli testjoin -D $AD' >/dev/null"
    fi
    check "$1: a Kerberos ticket as the machine (${acct:-none in its keytab})" \
        "[ -n '$acct' ] && $2 'kinit -k \"$q\" && klist | grep -q krbtgt'"
    check "$1: $PERSON resolves through SSSD (cache cleared first)" "$2 'sss_cache -E; id $PERSON@$AD' >/dev/null"
    check "$1: the DC ($dc) resolves through fabric's DNS" "[ -n '$dc' ] && $2 'getent hosts $dc' >/dev/null"
    check "$1: no failed sssd unit (2.1.6.95)" "[ -z \"\$($2 'systemctl --failed --no-legend | grep sssd')\" ]"
}
# Purpose: every joined client checked after a step (3.1.5.11).
client_check() {   # $1 the step
    echo "--- clients after: $1"
    linux_ok "$1, the fabric host's own join" F
    linux_ok "$1, ub26-2" L
    check "$1, ws25-1: its secure channel to the DC holds" "W 'Test-ComputerSecureChannel' | grep -q True"
    check "$1, ws25-1: nltest finds the DC" "W 'nltest /dsgetdc:$AD' | grep -qi 'DC: '"
    check "$1, ws25-1: the DC resolves" "W 'Resolve-DnsName $(dc_fqdn) -Type A' | grep -q '$AD'"
}
# Purpose: the members' DNS pointed at fabric's address (as a network's DHCP would hand it out).
members_dns() {   # $1 fabric's address
    # a member fabric's join set up keeps the address in managed.env, which its hourly check puts back (4.2.4.2 step 5)
    # first a check under way is let finish: the floor's fabric-managed takes no lock, and one started before the
    # change wrote the old address back (run 16, 2.3.1.42); 4.2.4.2 step 5 says the same
    L "if [ -f /etc/fabric/managed.env ]; then while systemctl is-active -q fabric-managed.service; do sleep 1; done; sed -i 's/^FABRIC_DNS=.*/FABRIC_DNS=$1/' /etc/fabric/managed.env && fabric-managed apply; fi"
    if L 'test -f /etc/fabric/managed.env' >/dev/null 2>&1; then
        check "the member's fabric DNS drop-in names $1 (4.2.4.2 step 5)" \
            "L 'grep -qx DNS=$1 /etc/systemd/resolved.conf.d/fabric.conf'"
    fi
    L "resolvectl dns \"\$(ip route get $1 | awk '{for (i=1;i<NF;i++) if (\$i==\"dev\") print \$(i+1)}')\" $1"
    W "Get-NetIPAddress -IPAddress $WIN | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex \$_.InterfaceIndex -ServerAddresses $1 }"
}

if wants join; then
    : "${FROM_DEB:?FROM_DEB: the .deb of the floor release, v0.8.0 from GitHub}"
    echo "=== join: fabric at the floor, then the members"
    FLOOR="clean: its setup finished at the first run"
    if ! bash "$REPO/scripts/lab/install_dev_build.sh" "$FABRIC" "$FROM_DEB" "$REPO/tests/lab/joined_vars.yaml"; then
        # nothing runs on a host the package did not reach (2026-11-01: apt's mirror mid-sync)
        F 'command -v fabricctl' >/dev/null 2>&1 || stop "the floor's package did not install (apt's output above)"
        # 0.8.0's known first-start issue (2.2.2.1, fixed in 0.9.0 by 1.2.4.5): the workaround an operator is given,
        # setup run again, once; reported apart from the checks, so a stopped first run is never hidden
        FLOOR="KNOWN ISSUE: its first setup stopped (0.8.0, 2.2.2.1); setup run again, once"
        echo "KNOWN the floor's $FLOOR"
        F 'fabricctl setup --file /root/lab-vars.yaml --non-interactive --yes --approve all --admin-password-file /root/lab-admin-pw' |
            tail -2
    fi
    check "fabric at the floor: doctor passes" "F 'fabricctl doctor' >/dev/null" || stop "the floor is not up"
    fp=$(F "openssl x509 -noout -fingerprint -sha256 -in /opt/stepca/data/certs/root_ca.crt | cut -d= -f2")
    # a captured value goes into a later command only when it is what it should be, never as text to run
    [[ "$fp" =~ ^([0-9A-F]{2}:){31}[0-9A-F]{2}$ ]] || stop "no root CA fingerprint from the fabric VM"
    members_dns "$FABRIC"
    # a machine just booted: the floor's join does not wait for dpkg's lock (run 22: unattended-upgrades held it, 2.3.1.50)
    L 'systemctl stop unattended-upgrades.service apt-daily.service apt-daily-upgrade.service 2>/dev/null
       for _ in $(seq 1 120); do fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || exit 0; sleep 5; done; exit 1' ||
        stop "dpkg's lock on ub26-2 was not let go"
    # the floor's own way, as 0.8.0's page gave it; this build's way is the fresh step (2.1.1.85)
    L "wget -nv -O /root/join-linux.sh http://$FABRIC/certs/join-linux.sh" >/dev/null
    # the one-time password goes from add-machine's output to the join's standard input: never an argument or a file
    F "fabricctl domain add-machine g23-vm-ub26-2 --type server | sed -n '/shown once/{n;p}'" |
        ssh "${SSH[@]}" "labadmin@$LINUX" "sudo bash /root/join-linux.sh $fp --one-time" 2>&1 | tail -3
    # the pipe's status is tail's: what the join left is the proof (run 22 went on with a member that never joined)
    L 'test -s /etc/fabric/managed.env' || stop "ub26-2's floor join did not happen"
    # Windows' OpenSSH hands PowerShell's [Console]::In only what is there when the session opens (a line sent seconds
    # later never arrives: 3.1.5.11 step 2, 2026-11-01), so the line is read here first, kept in this shell's memory
    # only (read and printf are builtins: never on a command line), and only then does the session open, with it
    F "fabricctl domain add-machine g23-vm-ws25-1 --type server | sed -n '/shown once/{n;p}'" | {
        IFS= read -r line
        [ -n "$line" ] || echo "FAIL ws25-1: add-machine printed no one-time password" >&2
        # a pre-created account's one-time password is the machine password (an unsecured join, no user: options
        # 0xC1 = join domain, unsecure, machine password passed); Add-Computer's PasswordPass refused the user name a
        # PSCredential must carry ("Machine password and the user account are passed. Error out.", 2026-11-01)
        printf '%s\n' "$line" | ssh "${SSH[@]}" "labadmin@$WIN" "powershell -NoProfile -Command \"\$r = (Get-WmiObject Win32_ComputerSystem).JoinDomainOrWorkgroup('$AD', [Console]::In.ReadLine(), \$null, \$null, 0xC1).ReturnValue; 'join: ' + \$r; if (\$r -eq 0) { Restart-Computer -Force }\"" 2>&1 | tail -3
        unset line
    }
    sleep 30; up "$WIN"
    client_check "the join (0.8.0)"
fi
if wants upgrade; then
    : "${TO_DEB:?TO_DEB: the .deb built from the branch, 3.1.5.9 step 1}"
    echo "=== upgrade: $(basename "$TO_DEB") over the floor"
    # the branch's version, from the file's name; used only when it is a Debian version (never as text to run)
    to_ver=$(basename "$TO_DEB" | sed -E 's/^fabricctl_(.*)_all\.deb$/\1/')
    [[ "$to_ver" =~ ^[0-9][0-9A-Za-z.~+-]*$ ]] || stop "TO_DEB's name gives no version ($(basename "$TO_DEB"))"
    scp -q "${SSH[@]}" "$TO_DEB" "labadmin@$FABRIC:/tmp/fabricctl-to.deb"
    # a branch build sorts above the floor (3.1.5.9 step 1): apt refuses a downgrade, and runs 5 to 8 went on after
    # "Packages were downgraded and -y was used without --allow-downgrades" with the floor still installed (2.3.1.33)
    F "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /tmp/fabricctl-to.deb >/dev/null && rm -f -- /tmp/fabricctl-to.deb" ||
        stop "the branch's package did not install (apt's output above)"
    have_ver=$(F 'dpkg-query -W -f="\${Version}" fabricctl' | tr -dc '0-9A-Za-z.~+-')
    check "the branch's package is installed ($to_ver; dpkg has $have_ver)" "[ '$have_ver' = '$to_ver' ]" ||
        stop "the floor's package is still installed"
    check "the upgrade's setup finishes" "F 'fabricctl setup --non-interactive --yes --approve all' >/dev/null"
    client_check "the upgrade"
fi
if wants place; then
    echo "=== place: ub26-2 and ws25-1 moved into an admin's OU at the domain's root (1.8.8.5, 2.1.6.106)"
    echo "INFO the host's own name before the move: $(on "$FABRIC" 'getent hosts "$(hostname)" || echo "not found"; grep -n "$(hostname)" /etc/hosts || echo "not in /etc/hosts"' | tr '\n' ' ')"
    # two people, one allowed on ub26-2 by a grant and one not, so the compare proves both ways (2.3.1.41's weakness):
    # placeok in place-crew, a grant of remote sign-in and sudo of /usr/bin/id on the host group hosts-placed
    # (ub26-2 alone); placeno in no grant. Their one-time passwords are discarded, never printed or logged.
    for who in placeok placeno; do
        F "fabricctl people add $who --first Place --last ${who#place} --email $who@$DOMAIN >/dev/null" ||
            stop "the place step's person $who was not made"
    done
    F "fabricctl domain group create place-crew --description 'the place step' >/dev/null &&
       fabricctl domain group members place-crew add placeok >/dev/null &&
       fabricctl machines group create placed >/dev/null && fabricctl machines group add placed g23-vm-ub26-2 >/dev/null &&
       fabricctl domain grant add place-ok --who place-crew --where hosts-placed --signin remote --sudo /usr/bin/id >/dev/null" ||
        stop "the place step's grant was not made"
    # what ub26-2 gives each before the move: sssd's access check (the grants' GPOs, PAM's account phase) and sudo;
    # Windows' applied GPOs and local Administrators; the same after it
    l_one() { L "sssctl user-checks $1@$AD -a acct -s sshd 2>&1 | grep -io 'pam_acct_mgmt: .*'; sudo -l -U $1@$AD 2>&1 | grep -E '^ +\\(' | sort"; }
    l_state() { L 'sss_cache -E; systemctl restart sssd; sleep 5' >/dev/null; echo "ok: $(l_one placeok | tr '\n' ' ')"; echo "no: $(l_one placeno | tr '\n' ' ')"; }
    # the grant reaches ub26-2 through its GPO and sudo rules: wait for it (up to 10 minutes) before the first read
    for _ in $(seq 1 20); do
        l_state | grep -q '^ok: pam_acct_mgmt: Success' && break; sleep 30
    done
    w_state() { W "gpupdate /target:computer /force | Out-Null; ((gpresult /r /scope computer) -match 'fabric' | ForEach-Object { \$_.Trim() } | Sort-Object) -join ';'; ((net localgroup Administrators | Select-Object -Skip 6) | Sort-Object) -join ';'"; }
    before_l=$(l_state); before_w=$(w_state)
    echo "INFO before: ub26-2: ${before_l//$'\n'/ | }; ws25-1: ${before_w//$'\n'/ | }"
    check "an admin's own OU made under OU=machines: machines/branch (2.1.6.101)" \
        "F 'fabricctl domain ou create machines branch' >/dev/null"
    check "an admin's own OU made at the domain's root: lab-root (2.1.6.101)" \
        "F 'fabricctl domain ou create / lab-root' >/dev/null"
    check "negative: a machine is not moved into OU=service-accounts, saying why" \
        "! F 'fabricctl domain machine move g23-vm-ub26-2 service-accounts' >/tmp/place.out 2>&1 && grep -q 'service accounts only' /tmp/place.out"
    check "ub26-2 moved to lab-root, out of OU=machines" "F 'fabricctl domain machine move g23-vm-ub26-2 lab-root' >/dev/null"
    check "ws25-1 moved to lab-root, out of OU=machines" "F 'fabricctl domain machine move g23-vm-ws25-1 lab-root' >/dev/null"
    check "negative: the fabric host's own account stays where fabric put it (2.1.6.100)" \
        "! F 'fabricctl domain machine move g23-vm-ub24-1 lab-root' >/dev/null 2>&1"
    sleep 60
    after_l=$(l_state); after_w=$(w_state)
    echo "INFO after: ub26-2: ${after_l//$'\n'/ | }; ws25-1: ${after_w//$'\n'/ | }"
    check "before the move: placeok allowed on ub26-2 (access check Success, sudo /usr/bin/id), placeno refused" \
        "printf '%s' '${before_l//\'/}' | grep -q '^ok: pam_acct_mgmt: Success.*/usr/bin/id' &&
         printf '%s' '${before_l//\'/}' | grep -q '^no: pam_acct_mgmt: Permission denied'"
    check "before the move: ws25-1 takes the Windows baseline, linked at the domain's root since 0.9.1 (2.1.6.106)" \
        "printf '%s' '${before_w//\'/}' | grep -q 'Windows baseline'"
    check "ub26-2 in lab-root: placeok still allowed and placeno still refused, as before (the GPOs at the root)" \
        "[ -n '${before_l//\'/}' ] && [ '${before_l//\'/}' = '${after_l//\'/}' ]"
    check "ws25-1 in lab-root: the same fabric GPOs applied and the same local Administrators as before" \
        "[ -n '${before_w//\'/}' ] && [ '${before_w//\'/}' = '${after_w//\'/}' ]"
    client_check "machines moved into an admin's OU"
fi
if wants images; then
    echo "=== images: every image updated and rolled back"
    # run on the VM itself (--local): update.sh reads previous.yaml with Python, which Git Bash does not have
    F "install -d -m 0700 /root/imgtest" >/dev/null
    for f in update.sh host_images.py previous.yaml; do
        scp -q "${SSH[@]}" -o "HostKeyAlias=$FIRST" "$REPO/tests/images/$f" "labadmin@$FABRIC:/tmp/imgtest-$f"
        F "mv /tmp/imgtest-$f /root/imgtest/$f"
    done
    check "every image's update and rollback (tests/images/update.sh --local)" \
        "F 'bash /root/imgtest/update.sh --local' | tail -3 | grep -q ' 0 failed'"
    client_check "every image updated and rolled back"
fi
if wants restart; then
    echo "=== restart: the stack, then the VM"
    check "fabricctl stop, then start" "F 'fabricctl stop && fabricctl start' >/dev/null"
    client_check "a restart of the stack"
    F "systemctl reboot" >/dev/null; sleep 30
    check "the fabric VM back after a reboot, doctor passes" "up $FABRIC && sleep 120 && F 'fabricctl doctor' >/dev/null"
    client_check "a reboot"
fi
if wants restore; then
    echo "=== restore: an export, then fabric back from it"
    check "uninstall with an export" "F 'fabricctl uninstall --yes --export /root/fabric-export' >/dev/null"
    check "restore from it" "F 'fabricctl restore /root/fabric-export --yes' >/dev/null"
    client_check "a restore from an export"
fi
# Steps move and rename follow the operators' procedure, 4.2.4.2 and 4.2.4.3, step for step (2.1.1.73).
# Purpose: the zone's records the menu lists (`sudo fabricctl --interactive`, 1, 1: 4.4.1), one per line as
#          "<n>) [<type>] <name> -> <value>", colours dropped. Read only: answers b, b, q.
zone_list() {
    F "printf '1\n1\nb\nb\nq\n' | TERM=dumb fabricctl --interactive 2>/dev/null" | sed 's/\x1b\[[0-9;]*m//g' |
        grep -E '^ *[0-9]+\) \[[A-Z]+\] '
}
# Purpose: 4.2.4.7 as written, on the host: each name asked at fabric's own address gives the new address alone, and
#          /etc/hosts names the DC at most once, at it.
only_new() {   # $1 the step; $2 the host's name now
    local out dc ad
    dc=$(dc_fqdn); ad=${dc#*.}
    out=$(F "for n in $2.$DOMAIN $DOMAIN ca.$DOMAIN $dc $ad; do echo \"\$n: \$(dig +short @$MOVED \"\$n\" | tr '\n' ' ')\"; done")
    printf '%s\n' "$out" | sed 's/^/    /'
    check "$1: 4.2.4.7, each name gives $MOVED alone, never $FIRST" \
        "[ \$(printf '%s\n' \"\$out\" | grep -c ' $MOVED \$') -eq 5 ] && ! printf '%s\n' \"\$out\" | grep -qF '$FIRST'"
    check "$1: 4.2.4.7, /etc/hosts names the DC at most once, at $MOVED" \
        "[ \$(F 'grep -c \"$dc\" /etc/hosts' | tr -dc 0-9) -le 1 ] && ! F 'grep -F \"$dc\" /etc/hosts' | grep -qF '$FIRST'"
}
if wants move; then
    echo "=== move: $FABRIC to $MOVED (4.2.4.2)"
    # ub26-2 was really joined by the floor's script: refreshed by the operators' procedure 4.6.6.12 (2.1.1.84)
    fp=$(F "openssl x509 -noout -fingerprint -sha256 -in /opt/stepca/data/certs/root_ca.crt | cut -d= -f2")
    [[ "$fp" =~ ^([0-9A-F]{2}:){31}[0-9A-F]{2}$ ]] || stop "no root CA fingerprint from the fabric VM"
    FM=/usr/local/sbin/fabric-managed; DROPIN=/etc/systemd/resolved.conf.d/fabric.conf
    # only the sums: sudo's own warning comes and goes while resolved restarts (2.3.1.42); a file gone drops its line
    sums() { L "sha256sum $FM $DROPIN /etc/fabric/managed.env /etc/ssh/sshd_config.d/10-fabric.conf 2>/dev/null" | grep -E '^[0-9a-f]{64} '; }
    floor_script() { L "grep -c 'flock 9' $FM" | grep -qx 0; }
    check "4.6.6.12 step 1: ub26-2 still has the floor's script, as step 1 tells" floor_script
    # the one fetch of 4.6.6.12: HTTPS, the root it trusts, by address (a member cut off has no name for fabric)
    # --capath too: Ubuntu's curl keeps /etc/ssl/certs beside a --cacert, which holds fabric's root here (run 21, 2.3.1.49)
    OWN=$(on "$FABRIC" 'hostname -s' 2>/dev/null | tr -dc 'a-zA-Z0-9-' | tr 'A-Z' 'a-z').$DOMAIN
    TRUST="--capath /usr/local/share/ca-certificates --resolve $OWN:443:$FABRIC https://$OWN/certs/join-linux.sh"
    GET="curl -fsS --cacert /usr/local/share/ca-certificates/fabric-root-ca.crt $TRUST -o /root/join-linux.sh"
    check "4.6.6.12 step 2: the installer fetched by HTTPS at fabric's address, verified by the root the member trusts" "L '$GET'"
    check "negative: the same fetch against a root it does not trust: refused" \
        "L 'openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -subj /CN=other -days 1 -out /tmp/other.pem 2>/dev/null; ! curl -fsS --cacert /tmp/other.pem $TRUST -o /dev/null 2>/dev/null'"
    check "the certificates page shows the refresh, with the fetch by address"         "L 'wget -qO- http://$FABRIC/certs/' | grep -qF -- '$TRUST'"
    was=$(sums)
    check "negative: --refresh, a fingerprint it does not trust: refused, nothing changed" \
        "L 'bash /root/join-linux.sh $(printf '0%.0s' {1..64}) --refresh' 2>&1 | grep -q 'not the fingerprint given' && [ \"\$(sums)\" = \"\$was\" ]"
    L "cp /etc/fabric/managed.env /root/env.kept; sed -i 's/^DC=.*/DC=nothing-here.invalid/' /etc/fabric/managed.env" >/dev/null
    was_bad=$(sums)
    check "negative: --refresh, the DC not answering: refused, and script, settings and DNS as they were" \
        "L 'bash /root/join-linux.sh $fp --refresh' 2>&1 | grep -q 'as it was' && [ \"\$(sums)\" = \"\$was_bad\" ]"
    L "cp /root/env.kept /etc/fabric/managed.env" >/dev/null
    check "...and the floor's script still there, its timer running" \
        "floor_script && L 'systemctl is-active --quiet fabric-managed.timer'"
    # what the floor's fault leaves: its own remove, as run 19's ub26-2 did to itself (2.3.1.47)
    dc=$(dc_fqdn)
    # members_dns gave its link fabric's address by hand, which a real member has not: back to what its netplan says, or
    # it is not cut off at all (run 21 "recovered" a member still resolving through that: 2.3.1.49). sssd restarted, so
    # its KDC file, which still names the DC's address, goes as it does in time on a real member
    dev=$(L "ip route get $FABRIC" | awk '{for (i=1;i<NF;i++) if ($i=="dev") print $(i+1)}')
    L "$FM remove; resolvectl revert $dev; systemctl try-restart systemd-resolved; systemctl restart sssd; resolvectl flush-caches; sleep 3" >/dev/null
    ticket() { L '. /etc/fabric/managed.env; kinit -k -c /tmp/refresh.cc "${MACHINE^^}\$@$REALM"' >/dev/null 2>&1; }
    INFO_DNS=$(L 'resolvectl status' | grep -E 'DNS Servers' | tr -s ' ' | tr '\n' ';')
    echo "INFO ub26-2's DNS, cut off: $INFO_DNS"
    check "the floor's fault reproduced: no drop-in" "! L 'test -e $DROPIN'"
    check "...the DC's name does not resolve" "! L 'getent hosts $dc' >/dev/null 2>&1"
    check "...and no ticket as the machine" "! ticket"
    # a check running: the refresh has to wait it out (its service made to take 15 s; a floor script has no lock)
    L "mkdir -p /etc/systemd/system/fabric-managed.service.d; printf '[Service]\nExecStartPre=/bin/sleep 15\n' > /etc/systemd/system/fabric-managed.service.d/lab-slow.conf; systemctl daemon-reload; systemctl start --no-block fabric-managed.service" >/dev/null
    out=$(L "$GET; bash /root/join-linux.sh $fp --refresh" 2>&1); printf '%s\n' "$out" | sed 's/^/    /'
    L "rm -rf /etc/systemd/system/fabric-managed.service.d; systemctl daemon-reload" >/dev/null
    check "4.6.6.12 step 3: --refresh on the cut-off member: waited for the running check, refreshed, in fabric-managed" \
        "printf '%s' \"\$out\" | grep -q 'waiting for a running check' && printf '%s' \"\$out\" | grep -q \"refreshed to this build's\" && printf '%s' \"\$out\" | grep -q 'in fabric-managed, its configuration applied'"
    check "...its timer running again, nothing left behind" \
        "L 'systemctl is-active --quiet fabric-managed.timer; ! ls -d /usr/local/sbin/.fabric-refresh* 2>/dev/null'"
    # with its link still on what netplan says: fabric's drop-in alone brought it back
    check "the fault gone: the drop-in back, the DC's name resolves, a ticket as the machine" \
        "L 'test -e $DROPIN' && L 'getent hosts $dc' >/dev/null 2>&1 && ticket"
    client_check "a refresh"
    L "resolvectl dns $dev $FABRIC" >/dev/null      # as members_dns had it, for the steps after this one
    check "--refresh again: the same result, saying so" \
        "L 'bash /root/join-linux.sh $fp --refresh' | grep -q \"already this build's\""
    check "ub26-2 has this build's fabric-managed (it follows an announcement)" "L 'grep -q managed.next /usr/local/sbin/fabric-managed'"
    # step 1a (2.1.1.79, 1.4.1.8.7): announced first, then the members told, each as its own timer would
    check "negative: move prepare refuses the host's own address, saying why" \
        "F 'fabricctl move prepare $FABRIC' 2>&1 | grep -q 'address now'"
    check "4.2.4.2 step 1a: move prepare $MOVED" "F 'fabricctl move prepare $MOVED' | grep -q 'announced'"
    check "...move status names both addresses" "F 'fabricctl move status' | grep -q 'from $FABRIC to $MOVED'"
    L 'fabric-managed check' >/dev/null
    check "ub26-2 follows it: both addresses, old first, in its DNS drop-in" \
        "L 'grep -qx \"DNS=$FABRIC $MOVED\" /etc/systemd/resolved.conf.d/fabric.conf'"
    W 'gpupdate /target:computer /force | Out-Null' >/dev/null
    # its task runs when it is registered: a moment after gpupdate (run 18: the DNS Client policy was ignored, 2.3.1.44)
    for _ in $(seq 1 12); do [ "$(win_dns)" = "$FABRIC $MOVED" ] && break; sleep 10; done
    check "ws25-1 follows it: both addresses, old first, on its adapter" \
        "[ \"\$(win_dns)\" = '$FABRIC $MOVED' ]"
    check "...by the Group Policy Preferences task, also on NETLOGON's 5719 and every 5 minutes while it is announced" \
        "W \"Export-ScheduledTask -TaskName 'fabric secure channel' | Out-String\" | grep -q '<Interval>PT5M</Interval>'"
    echo "INFO ws25-1's DNS servers as it uses them: $(W 'ipconfig /all' | grep -iA2 'DNS Servers' | tr -s ' \r\n' ' ')"
    # 4.2.4.2 step 2: the netplan file's address, applied by systemd 10 s later, so this session has ended before the
    # address changes under it (a nohup'd apply kept it open: run 5, 2026-11-01, ssh waited on the dead connection for
    # good); and a hard limit with the keepalives, so no session can hang the campaign
    timeout 60 ssh "${SSH[@]}" "labadmin@$FABRIC" "sudo bash -lc $(printf '%q' "sed -i 's#$FABRIC/24#$MOVED/24#' /etc/netplan/*.yaml && systemd-run --quiet --on-active=10 --unit=fabric-move-netplan netplan apply")" </dev/null >/dev/null 2>&1
    rc=$?
    check "4.2.4.2 step 2: the new address in netplan, applied detached (ssh exit $rc)" "[ $rc -eq 0 ]"
    sleep 30; FABRIC_OLD=$FABRIC; FABRIC=$MOVED
    check "the fabric VM no longer answers at $FABRIC_OLD" "! on $FABRIC_OLD true >/dev/null 2>&1"
    check "the fabric VM answers at $MOVED" "up $MOVED" || stop "the fabric VM is not reachable at $MOVED"
    # step 3: host_ip in vars.yaml, then the apply
    F "sed -i 's/^host_ip: .*/host_ip: $MOVED/' /opt/fabric/config/vars.yaml"
    check "4.2.4.2 step 3: host_ip applied" "F 'fabricctl --apply' >/dev/null"
    # step 4: the host's own join
    check "4.2.4.2 step 4: the member step" "F 'fabricctl setup --step member --non-interactive --approve member' >/dev/null"
    # since 0.9.1 the apply and the member step leave nothing at the old address (2.1.1.74): no clean-up by hand
    # the name read without sudo: `on` keeps a command's stderr, and sudo's own warnings must not join the name (run 15)
    HOSTNOW=$(on "$FABRIC" hostname | tr -dc 'a-z0-9-')
    # how the moved host finds its own name (run 15: sudo once could not, "Temporary failure in name resolution")
    echo "INFO the host's own name after the move: $(on "$FABRIC" 'getent hosts "$(hostname)" || echo "not found"; grep -n "$(hostname)" /etc/hosts || echo "not in /etc/hosts"' | tr '\n' ' ')"
    DCF=$(dc_fqdn)
    check "after the apply: no record at $FABRIC_OLD in fabric's zone (the menu's list)" \
        "zone_list >/dev/null && ! zone_list | grep -qF -- '-> $FABRIC_OLD'"
    check "after the member step: /etc/hosts has no line for the DC at $FABRIC_OLD" "! F 'grep -F \"$DCF\" /etc/hosts' | grep -qF '$FABRIC_OLD'"
    # step 5: nothing done by hand on the members (2.1.1.79): each settles as its own timer and task would
    L 'fabric-managed check' >/tmp/settle.out 2>&1; cat /tmp/settle.out | tail -2
    MEMBERS_OK=1
    check "ub26-2 settled by itself: the new address alone in its DNS drop-in and managed.env" \
        "L 'grep -qx DNS=$MOVED /etc/systemd/resolved.conf.d/fabric.conf && grep -qx FABRIC_DNS=$MOVED /etc/fabric/managed.env && ! test -e /etc/fabric/managed.next'" || MEMBERS_OK=0
    check "ub26-2: SSSD restarted by it, its KDC file at $MOVED, a person found" \
        "L 'sleep 5; id $PERSON@$AD >/dev/null; grep -qx $MOVED /var/lib/sss/pubconf/kdcinfo.${AD^^}'" || MEMBERS_OK=0
    # Windows: its task, every 5 minutes and on NETLOGON's 5719; nothing run by hand
    W_OK=0
    for _ in $(seq 1 30); do
        if W 'Test-ComputerSecureChannel' | grep -q True; then W_OK=1; break; fi
        sleep 30
    done
    echo "INFO ws25-1: 5719s logged: $(W "(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='NETLOGON';Id=5719} -MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object).Count"); the task last ran: $(W "(Get-ScheduledTaskInfo -TaskName 'fabric secure channel').LastRunTime")"
    check "ws25-1 has its secure channel, nothing run by hand" "[ $W_OK -eq 1 ]" || MEMBERS_OK=0
    W 'gpupdate /target:computer /force | Out-Null' >/dev/null
    for _ in $(seq 1 12); do [ "$(win_dns)" = "$MOVED" ] && break; sleep 10; done
    check "ws25-1's adapter names the new address alone after the move, by the task" \
        "[ \"\$(win_dns)\" = '$MOVED' ]" || MEMBERS_OK=0
    check "the announcement went with the move: move status says none" "F 'fabricctl move status' | grep -q 'no move announced'"
    if [ "$MEMBERS_OK" -eq 0 ]; then    # so the later steps still run: the procedure by hand, reported as the failure above
        echo "INFO a member did not follow by itself: 4.2.4.2 step 5 by hand, so the rest of the run can go on"
        members_dns "$MOVED"
        L 'resolvectl flush-caches; systemctl restart sssd' >/dev/null
        W 'ipconfig /flushdns; nltest /sc_reset:'"$AD" >/dev/null
    fi
    # step 6: 4.2.4.7, doctor, and a client finds fabric at its new address
    only_new "4.2.4.2 step 6" "$HOSTNOW"
    check "4.2.4.2 step 6: doctor passes" "F 'fabricctl doctor' >/dev/null"
    check "fabric's DNS answers at $MOVED, not at $FABRIC_OLD" \
        "L 'getent ahostsv4 info.$DOMAIN' | grep -q '$MOVED' && ! L 'getent ahostsv4 info.$DOMAIN' | grep -q '$FABRIC_OLD'"
    client_check "a move to a new address"
fi
if wants rename; then
    echo "=== rename: the fabric VM to $RENAMED (4.2.4.3, through break glass: 2.1.6.104)"
    dc_before=$(dc_fqdn)
    OLDNAME=$(on "$FABRIC" hostname | tr -dc 'a-z0-9-')
    # the refusal (1.6.11.14): the old way, hostname in vars.yaml then the apply, is refused on a DC's host
    F "sed -i 's/^hostname: .*/hostname: $RENAMED/' /opt/fabric/config/vars.yaml"
    out=$(F 'fabricctl --apply 2>&1')
    check "negative: an apply with another hostname on the DC's host is refused, naming break glass and 4.2.4.3" \
        "printf '%s\n' \"\$out\" | grep -q 'renamed only through break glass' && printf '%s\n' \"\$out\" | grep -q 'fabricctl admin rename-host $RENAMED'"
    F "sed -i 's/^hostname: .*/hostname: $OLDNAME/' /opt/fabric/config/vars.yaml"
    # 4.2.4.3 step 2: through break glass; step 3: the apply
    out=$(F "fabricctl admin rename-host $RENAMED --reason 'the joined campaign (3.1.5.11)' 2>&1"); rc=$?
    printf '%s\n' "$out" | tail -3 | sed 's/^/    /'
    check "4.2.4.3 step 2: fabricctl admin rename-host (exit $rc)" "[ $rc -eq 0 ]"
    check "4.2.4.3 step 3: the apply" "F 'fabricctl --apply' >/dev/null"
    check "the DC keeps its own name ($dc_before)" "[ \"\$(dc_fqdn)\" = '$dc_before' ]"
    # step 4: the host's own join moves to an account under the new name
    check "4.2.4.3 step 4: the member step" "F 'fabricctl setup --step member --non-interactive --approve member' >/dev/null"
    # step 5: nothing to clean up since 0.9.1 (2.1.1.74): fabric's names follow the new name, the landing alias with them
    check "4.2.4.3 step 5: no record names $OLDNAME in fabric's zone (the menu's list)" \
        "zone_list >/dev/null && ! zone_list | grep -qE '\] ($OLDNAME -> |[a-z0-9-]+ -> $OLDNAME\$)'"
    check "4.2.4.3 step 5: each of fabric's aliases is in the zone once, under $RENAMED" \
        "[ \$(zone_list | grep -cE '\[CNAME\] (ca|dns|sso|vault|ntp) -> $RENAMED\$') -eq 5 ]"
    L 'resolvectl flush-caches' >/dev/null
    W 'ipconfig /flushdns' >/dev/null
    # step 6: 4.2.4.7; its keytab holds the new name's account; doctor passes (adcli testjoin: in client_check)
    only_new "4.2.4.3 step 6" "$RENAMED"
    check "4.2.4.3 step 6: 4.2.4.7, $OLDNAME.$DOMAIN gives nothing" "[ -z \"\$(F 'dig +short @$MOVED $OLDNAME.$DOMAIN')\" ]"
    check "4.2.4.3 step 6: the keytab holds ${RENAMED^^}\$" "F 'klist -k /etc/krb5.keytab' | grep -qF '${RENAMED^^}\$@'"
    check "4.2.4.3 step 6: doctor passes" "F 'fabricctl doctor' >/dev/null"
    client_check "the host renamed"
fi
if wants fresh; then
    echo "=== fresh: ub26-2 joined again by this build's steps, as the certificates page gives them (4.6.6.2, 2.1.1.85)"
    fp=$(F "openssl x509 -noout -fingerprint -sha256 -in /opt/stepca/data/certs/root_ca.crt | cut -d= -f2")
    [[ "$fp" =~ ^([0-9A-F]{2}:){31}[0-9A-F]{2}$ ]] || stop "no root CA fingerprint from the fabric VM"
    # the page's block itself, entities decoded, its placeholders filled; here a one-time password, read from stdin
    # shellcheck disable=SC2016
    L "mkdir -p /root/fresh; rm -f /root/fresh/*; wget -qO- http://$FABRIC/certs/ | sed -n '/<pre id=\"join-steps\">/,/<\\/pre>/p' |
       sed 's/.*<code>//; s/<\\/code>.*//; s/&lt;/</g; s/&gt;/>/g; s/&amp;/\\&/g; s/<root CA SHA-256 from above>/$fp/; s/--user <directory admin>/--one-time/' > /root/fresh/.steps"
    check "the page's join steps fetch the root by HTTP and the script by HTTPS alone" \
        "L 'grep -q \"http://.*/certs/root-ca.crt root-ca.crt\" /root/fresh/.steps && grep -q \"pinned https://.*/certs/join-linux.sh\" /root/fresh/.steps && ! grep -qE \"http://[^ ]*join-linux\" /root/fresh/.steps'"
    was=$(L "sha256sum /etc/fabric/managed.env /etc/krb5.keytab /usr/local/sbin/fabric-managed" | grep -E '^[0-9a-f]{64} ')
    unchanged() { [ "$(L "sha256sum /etc/fabric/managed.env /etc/krb5.keytab /usr/local/sbin/fabric-managed" | grep -E '^[0-9a-f]{64} ')" = "$was" ]; }
    out=$(L "cd /root/fresh; sed 's/^FP=.*/FP=$(printf '00:%.0s' {1..31})00/' .steps > .wrong; bash .wrong; echo rc=\$?; ls -A | tr '\n' ' '" 2>&1)
    printf '%s\n' "$out" | sed 's/^/    /'
    check "negative: a wrong fingerprint: refused, saying why, the script neither fetched nor run, nothing changed" \
        "printf '%s' \"\$out\" | grep -q 'is not the fingerprint you gave' && printf '%s' \"\$out\" | grep -q rc=1 && ! printf '%s' \"\$out\" | grep -q ' join-linux.sh' && unchanged"
    # a root that is not fabric's, whose own fingerprint is held; the machine's store trusts fabric's: that must not count
    L 'openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -subj /CN=other -days 1 -out /tmp/other.pem 2>/dev/null' >/dev/null
    other=$(L 'openssl x509 -in /tmp/other.pem -noout -fingerprint -sha256 | cut -d= -f2')
    [[ "$other" =~ ^([0-9A-F]{2}:){31}[0-9A-F]{2}$ ]] || stop "no other root's fingerprint"
    out=$(L "cd /root/fresh; sed 's/^FP=.*/FP=$other/; s#http://[^ ]*/certs/root-ca.crt root-ca.crt#file:///tmp/other.pem root-ca.crt#' .steps > .other; bash .other; echo rc=\$?; ls -A | tr '\n' ' '" 2>&1)
    printf '%s\n' "$out" | sed 's/^/    /'
    check "negative: a root that is not fabric's: refused, saying why, the script not kept or run, nothing changed" \
        "printf '%s' \"\$out\" | grep -q 'did not prove itself' && printf '%s' \"\$out\" | grep -q rc=1 && ! printf '%s' \"\$out\" | grep -q ' join-linux.sh' && unchanged"
    # 4.6.6.11's way to join again under a new name, and the one-time password by the pipe, never an argument or a file
    FRESH=g23-fresh-1
    L "rm -f /etc/polkit-1/rules.d/10-fabric-hostname.rules /etc/krb5.keytab; hostnamectl set-hostname $FRESH" >/dev/null
    F "fabricctl domain add-machine $FRESH --type server | sed -n '/shown once/{n;p}'" |
        ssh "${SSH[@]}" "labadmin@$LINUX" "sudo bash -c 'cd /root/fresh && bash .steps'" 2>&1 | tail -3
    check "the fresh join: the steps fetched and ran this build's script, joined as $FRESH" \
        "L 'grep -qx MACHINE=$FRESH /etc/fabric/managed.env && test -s /root/fresh/join-linux.sh && grep -c \"flock 9\" /usr/local/sbin/fabric-managed | grep -qx 1'"
    client_check "a fresh join by this build's steps"
fi
echo
echo "FLOOR first setup: $FLOOR"
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
