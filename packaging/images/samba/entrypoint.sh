#!/bin/bash
# -----------------------------------------------------------------------
# fabric's Samba AD DC (manual 1.6.5): provision the domain once, or join
# it as a DC or RODC (JOIN_ROLE), then converge the settings fabric owns in
# smb.conf and run the DC in the foreground. A provisioned /data (its
# .fabric-provisioned marker) is reused, so every later start only
# converges; data without the marker is a failed attempt, cleared first. Secrets come as files, never on a
# command line: the Administrator's password (/run/secrets/admin_password),
# a join's credentials (/run/secrets/join.auth).
#
# env: REALM, NETBIOS, HOST_NAME (short), HOST_IP, INTERFACES, RPC_PORTS,
#      OLD_PASSWORD_MINUTES, KDC_TICKET_HOURS, KDC_RENEW_HOURS, KDC_SKEW_SECONDS; optional JOIN_ROLE (DC|RODC), JOIN_SERVER, JOIN_SITE (its AD site),
#      SAMBA_DEBUG
# -----------------------------------------------------------------------
set -euo pipefail
DATA=/data
CONF=$DATA/etc/smb.conf
export KRB5_CONFIG=$DATA/private/krb5.conf
# no CAP_SYS_ADMIN: Windows ACLs go into a user xattr instead of security.NTACL
OPTS=(--option="acl_xattr:security_acl_name = user.NTACL")

# Purpose: show the end of a failed provisioning or join log without any line naming a password (provisioning
#          prints the temporary administrator password it made).
# Inputs:  $1 — log file.
# Returns: 0, the filtered lines on stdout.
# Fails:   never.
# Feeds:   the provision and join branches below.
show_log() { grep -vi 'password' "$1" | tail -20 || true; }

# Purpose: remove what a failed provisioning or join left in /data, keeping the folders BIND mounts (etc,
#          bind-dns: a mount of a folder made anew would still show BIND the old one), emptied.
# Inputs:  none ($DATA).
# Returns: 0.
# Fails:   under set -e if find fails.
# Feeds:   the provision and join branches below.
clear_data() {
    find "$DATA" -mindepth 1 -maxdepth 1 ! -name etc ! -name bind-dns -exec rm -rf {} +
    find "$DATA/etc" "$DATA/bind-dns" -mindepth 1 -delete 2>/dev/null || true
}

# written only once provisioning or a join has fully succeeded: data without it is a failed attempt, never a domain
DONE=$DATA/.fabric-provisioned
if [ -f "$DONE" ]; then
    echo "domain data found: converging ${REALM,,}"
elif [ -n "${JOIN_ROLE:-}" ]; then
    echo "joining ${REALM,,} as $JOIN_ROLE through $JOIN_SERVER"
    clear_data
    mkdir -p "$DATA/etc"
    # the join registers the DC's name at every address of its interfaces: the LAN's alone here, never fabric_net's
    # gateway (2.1.2.15; a joined DC named it too, and the other DCs replicated to their own gateway: 2.3.1.32); the
    # gateway is added to the interfaces below, once joined
    samba-tool domain join "${REALM,,}" "$JOIN_ROLE" --server="$JOIN_SERVER" -A /run/secrets/join.auth \
        --targetdir="$DATA" --dns-backend=BIND9_DLZ --option="netbios name = $HOST_NAME" ${JOIN_SITE:+--site="$JOIN_SITE"} "${OPTS[@]}" \
        --option="interfaces = 127.0.0.1 $HOST_IP" --option="bind interfaces only = yes" \
        > /tmp/join.log 2>&1 || { show_log /tmp/join.log; exit 1; }
    rm -f /tmp/join.log
    touch "$DONE"
    echo "joined"
else
    echo "provisioning ${REALM,,}"
    clear_data
    # no --adminpass: provisioning makes a random one (and prints it: the log is discarded), replaced from the
    # secret file at once
    # interfaces limited from the start: provisioning otherwise guesses the host's IPv6 addresses (host network) and
    # publishes them as AAAA records the DC never answers on (2.1.6.29: IPv4 only)
    samba-tool domain provision --targetdir="$DATA" --server-role=dc --use-rfc2307 --dns-backend=BIND9_DLZ \
        --realm="$REALM" --domain="$NETBIOS" --host-name="$HOST_NAME" --host-ip="$HOST_IP" "${OPTS[@]}" \
        --option="interfaces = $INTERFACES" --option="bind interfaces only = yes" \
        > /tmp/provision.log 2>&1 || { show_log /tmp/provision.log; exit 1; }
    rm -f /tmp/provision.log
    python3 /usr/local/bin/set_password.py "$CONF" Administrator /run/secrets/admin_password
    touch "$DONE"
    echo "provisioned"
fi

# Purpose: set one [global] option of smb.conf to fabric's value (replaced if present, added if not), so every
#          Samba process sees it (winbindd reads smb.conf, not the master's --option).
# Inputs:  $1 — option name; $2 — value. Changes $CONF.
# Returns: 0.
# Fails:   under set -e if sed fails.
# Feeds:   the converge list below.
set_global() {
    if grep -qiE "^\s*$1\s*=" "$CONF"; then
        sed -i -E "s|^\s*$1\s*=.*|\t$1 = $2|I" "$CONF"
    else
        sed -i "/^\[global\]/a\\	$1 = $2" "$CONF"
    fi
}
set_global "interfaces" "$INTERFACES"
set_global "bind interfaces only" "yes"
set_global "server services" "-dns"
# the DC's own DNS records name the LAN address only, never fabric_net's gateway it also listens on (2.1.2.15)
set_global "dns update command" "/usr/sbin/samba_dnsupdate --current-ip=$HOST_IP"
# AD needs no NetBIOS: nothing binds 137-139
set_global "disable netbios" "yes"
set_global "rpc server dynamic port range" "$RPC_PORTS"
# PEAP-MSCHAPv2 (802.1X): Samba refuses MS-CHAPv2 by default
set_global "ntlm auth" "mschapv2-and-ntlmv2-only"
set_global "old password allowed period" "$OLD_PASSWORD_MINUTES"
# the Kerberos ticket policy (manual 1.6.12.9): the KDC's lifetimes, in hours (AD's defaults when not given)
set_global "kdc:user ticket lifetime" "${KDC_TICKET_HOURS:-10}"
set_global "kdc:service ticket lifetime" "${KDC_TICKET_HOURS:-10}"
set_global "kdc:renewal lifetime" "${KDC_RENEW_HOURS:-168}"
set_global "acl_xattr:security_acl_name" "user.NTACL"
# LDAPS with fabric's Step-CA certificate (2.1.5.3); Samba's own CA stays off
set_global "tls enabled" "yes"
set_global "tls certfile" "/tls/fullchain.pem"
set_global "tls keyfile" "/tls/privkey.pem"
set_global "tls cafile" "/tls/root_ca.crt"
set_global "ntp signd socket directory" "/run/samba/ntp_signd"
set_global "winbindd socket directory" "/run/samba/winbindd"
# never advertised (2.1.6.16, the owner's condition): no mDNS; SYSVOL and NETLOGON left out of share lists (Windows
# reads policy by its path, which hiding does not change)
set_global "multicast dns register" "no"

# Purpose: set one option of a share in smb.conf to fabric's value (replaced if present, added if not).
# Inputs:  $1 — share name as provisioning writes it (sysvol, netlogon); $2 — option name; $3 — value. Changes $CONF.
# Returns: 0.
# Fails:   under set -e if sed fails.
# Feeds:   the share list below.
set_share() {
    sed -i -E "/^\[$1\]/,/^\[/{/^\s*$2\s*=/Id}" "$CONF"
    sed -i "/^\[$1\]/a\\	$2 = $3" "$CONF"
}
set_share sysvol browseable no
set_share netlogon browseable no

# Group Policy between sites (manual 1.9.8.15): every 5 minutes, the GPO folders this DC does not own, from the DC
# that does (tini reaps it with the DC)
(
    sleep 60
    while true; do
        PYTHONDONTWRITEBYTECODE=1 python3 /fabric/pull_sysvol.py || true
        sleep 300
    done
) &

# Purpose: the clock skew the KDC allows (manual 1.6.12.9), in the krb5.conf the DC's Kerberos reads (KRB5_CONFIG):
#          `clockskew` in [libdefaults], replaced if present, added if not.
# Inputs:  $1 — seconds. Changes $KRB5_CONFIG (made with [libdefaults] when provisioning left none).
# Returns: 0.
# Fails:   under set -e if sed fails.
# Feeds:   the line below.
set_clockskew() {
    [ -f "$KRB5_CONFIG" ] || printf '[libdefaults]\n' > "$KRB5_CONFIG"
    grep -q '^\[libdefaults\]' "$KRB5_CONFIG" || printf '[libdefaults]\n' >> "$KRB5_CONFIG"
    if grep -qE '^\s*clockskew\s*=' "$KRB5_CONFIG"; then
        sed -i -E "s|^\s*clockskew\s*=.*|\tclockskew = $1|" "$KRB5_CONFIG"
    else
        sed -i "/^\[libdefaults\]/a\\	clockskew = $1" "$KRB5_CONFIG"
    fi
}
set_clockskew "${KDC_SKEW_SECONDS:-300}"

# runtime sockets live on /run (a tmpfs, or the host's folders for winbind and ntp_signd)
mkdir -p /run/samba/ntp_signd && chmod 750 /run/samba/ntp_signd
exec samba -s "$CONF" --foreground --no-process-group --debug-stdout ${SAMBA_DEBUG:+--debuglevel=$SAMBA_DEBUG}
