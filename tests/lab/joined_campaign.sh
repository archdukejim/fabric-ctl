#!/bin/bash
# -----------------------------------------------------------------------
# The lab's joined campaign (manual 3.1.5.11, decision 2.1.1.48): machines joined to fabric's domain checked through
# everything fabric does to itself. From Git Bash on gaming-23, after `start_lab.ps1 -Campaign joined` (rtr-1, ub24-1,
# ub26-2, ws25-1, each from its `clean` checkpoint). No Python runs here (Windows' python is a store stub): every check
# runs on the lab VMs over SSH with the lab key.
#
#   FROM_DEB=<fabricctl 0.8.0 .deb> TO_DEB=<the branch's .deb> tests/lab/joined_campaign.sh
#   [ONLY="join upgrade images restart restore move rename" picks steps; all by default, each needs those before it]
#
# The steps, each followed by client_check (the fabric host's own join, the Linux member ub26-2, the Windows member
# ws25-1: the machine's password still the DC's, a Kerberos ticket as the machine, a domain person resolved, the DC
# found through fabric's DNS, no failed sssd unit):
#   join     fabric at the floor (FROM_DEB, 0.8.0 until 1.0: 2.1.1.61) with tests/lab/joined_vars.yaml; ub26-2 and
#            ws25-1 joined with one-time passwords, piped from add-machine's output to the member (never an argument)
#   upgrade  TO_DEB installed over it, then setup unattended, as an operator upgrades
#   images   every image updated and rolled back: tests/images/update.sh --ssh (2.1.14.12)
#   restart  fabricctl stop and start, then the fabric VM rebooted
#   restore  uninstall --export, then restore from it (3.2.4)
#   move     the fabric VM moved from 10.88.0.10 to 10.88.0.13 by 4.2.4.2: netplan, host_ip applied, the member
#            step, the members' DNS moved
#   rename   the fabric VM renamed by 4.2.4.3: hostnamectl, hostname applied, the member step (the DC keeps
#            dc_name, 1.6.5.23; the keytab holds the new name)
# Afterwards the four VMs go back to `clean` (3.1.5.11 step 9).
# -----------------------------------------------------------------------
set -uo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
FABRIC=10.88.0.10; MOVED=10.88.0.13; LINUX=10.88.0.21; WIN=10.88.0.41
DOMAIN=lab.test; AD=ad.lab.test; PERSON=lab.admin; RENAMED=g23-vm-ub24-1b
ONLY="${ONLY:-join upgrade images restart restore move rename}"
SSH=(-i "$HOME/.ssh/g23_lab" -o "UserKnownHostsFile=$HOME/fabric-lab/known_hosts" -o BatchMode=yes -o ConnectTimeout=20)
PASS=0; FAIL=0
check() { if (set +o pipefail; eval "$2"); then echo "PASS $1"; PASS=$((PASS+1)); else echo "FAIL $1"; FAIL=$((FAIL+1)); return 1; fi; }
FLOOR="not run (no join step)"
# Purpose: end the campaign where a step it depends on did not happen; nothing after it runs on a half-built lab.
stop() { echo "STOP $1: the campaign ends here ($PASS passed, $FAIL failed)"; echo "FLOOR first setup: $FLOOR"; exit 1; }
wants() { case " $ONLY " in *" $1 "*) return 0 ;; esac; return 1; }
# Purpose: a command on a lab VM: its output without OpenSSH's notices, and the command's own exit status. The fabric
#          VM keeps its host key under its first address when it moves (HostKeyAlias).
on() {
    local out rc
    out=$(ssh "${SSH[@]}" -o "HostKeyAlias=$([ "$1" = "$MOVED" ] && echo "$FABRIC" || echo "$1")" "labadmin@$1" "$2" 2>&1)
    rc=$?
    printf '%s\n' "$out" | grep -v "post-quantum\|store now\|upgraded. See\|^$" || true
    return $rc
}
F() { on "$FABRIC" "sudo bash -lc $(printf '%q' "$1")"; }          # as root on the fabric VM (wherever it is now)
L() { on "$LINUX" "sudo bash -lc $(printf '%q' "$1")"; }           # as root on the Linux member
W() { on "$WIN" "powershell -NoProfile -Command \"$1\""; }           # on the Windows member (labadmin: an admin)
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
    L "wget -nv -O /root/join-linux.sh http://$FABRIC/certs/join-linux.sh" >/dev/null
    # the one-time password goes from add-machine's output to the join's standard input: never an argument or a file
    F "fabricctl domain add-machine g23-vm-ub26-2 --type server | sed -n '/shown once/{n;p}'" |
        ssh "${SSH[@]}" "labadmin@$LINUX" "sudo bash /root/join-linux.sh $fp --one-time" 2>&1 | tail -3
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
    scp -q "${SSH[@]}" "$TO_DEB" "labadmin@$FABRIC:/tmp/fabricctl-to.deb"
    F "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /tmp/fabricctl-to.deb >/dev/null && rm -f -- /tmp/fabricctl-to.deb"
    check "the upgrade's setup finishes" "F 'fabricctl setup --non-interactive --yes --approve all' >/dev/null"
    client_check "the upgrade"
fi
if wants images; then
    echo "=== images: every image updated and rolled back"
    # run on the VM itself (--local): update.sh reads previous.yaml with Python, which Git Bash does not have
    F "install -d -m 0700 /root/imgtest" >/dev/null
    for f in update.sh host_images.py previous.yaml; do
        scp -q "${SSH[@]}" -o "HostKeyAlias=10.88.0.10" "$REPO/tests/images/$f" "labadmin@$FABRIC:/tmp/imgtest-$f"
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
if wants move; then
    echo "=== move: $FABRIC to $MOVED (4.2.4.2)"
    # 4.2.4.2 step 2: the netplan file's address, applied detached (the address changes under this SSH session)
    F "sed -i 's#$FABRIC/24#$MOVED/24#' /etc/netplan/*.yaml && nohup setsid sh -c 'sleep 2; netplan apply' >/dev/null 2>&1 </dev/null &"
    sleep 20; FABRIC_OLD=$FABRIC; FABRIC=$MOVED
    check "the fabric VM answers at $MOVED" "up $MOVED"
    # step 3: host_ip in vars.yaml, then the apply
    F "sed -i 's/^host_ip: .*/host_ip: $MOVED/' /opt/fabric/config/vars.yaml"
    check "4.2.4.2 step 3: host_ip applied" "F 'fabricctl --apply' >/dev/null"
    # step 4: the host's own join
    check "4.2.4.2 step 4: the member step" "F 'fabricctl setup --step member --non-interactive --approve member' >/dev/null"
    # step 5: the clients' DNS (the lab's members have fixed addresses)
    members_dns "$MOVED"
    # step 6: doctor, and a client finds fabric at its new address
    check "4.2.4.2 step 6: doctor passes" "F 'fabricctl doctor' >/dev/null"
    check "fabric's DNS answers at $MOVED, not at $FABRIC_OLD" "L 'getent hosts info.$DOMAIN' | grep -q '$MOVED'"
    client_check "a move to a new address"
fi
if wants rename; then
    echo "=== rename: the fabric VM to $RENAMED (4.2.4.3)"
    dc_before=$(dc_fqdn)
    # 4.2.4.3 step 2: renamed as root; step 3: hostname in vars.yaml, then the apply
    F "hostnamectl set-hostname $RENAMED"
    F "sed -i 's/^hostname: .*/hostname: $RENAMED/' /opt/fabric/config/vars.yaml"
    check "4.2.4.3 step 3: hostname applied" "F 'fabricctl --apply' >/dev/null"
    check "the DC keeps its own name ($dc_before)" "[ \"\$(dc_fqdn)\" = '$dc_before' ]"
    # step 4: the host's own join moves to an account under the new name
    check "4.2.4.3 step 4: the member step" "F 'fabricctl setup --step member --non-interactive --approve member' >/dev/null"
    # step 5: its keytab holds the new name's account and doctor passes (adcli testjoin: in client_check)
    check "4.2.4.3 step 5: the keytab holds ${RENAMED^^}\$" "F 'klist -k /etc/krb5.keytab' | grep -qF '${RENAMED^^}\$@'"
    check "4.2.4.3 step 5: doctor passes" "F 'fabricctl doctor' >/dev/null"
    client_check "the host renamed"
fi
echo
echo "FLOOR first setup: $FLOOR"
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
