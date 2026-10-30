# Kea DHCPv4 + DHCP-DDNS 3.0 LTS from ISC's own signed apt repository (Debian
# trixie ships only 2.6; design 2.1.1.5), on the validated Debian base. The Kea
# version and the repository key's fingerprint come from images.lock.yaml:
# the build fails if the key is not ISC's, and installs exactly that version:
# every isc-kea package, isc-kea-common too (the others need its exact version;
# left to apt it took ISC's newest, 3.0.5, and the build failed: 2.3.1.32).
# The base is always given by the compose file (digest-pinned, no default).
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG BASE_IMAGE
LABEL org.fabric.base="${BASE_IMAGE}"

ARG KEA_VERSION
ARG KEA_REPO
ARG KEA_SUITE
ARG KEA_KEY_URL
ARG KEA_KEY_FINGERPRINT
ARG KEA_UID=609
ARG KEA_GID=609
# the service account's ids are baked in: a change rebuilds (images/needs_rebuild)
LABEL org.fabric.ids="${KEA_UID}:${KEA_GID}"
LABEL org.fabric.kea="${KEA_VERSION}"

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gpg tini \
 && curl -fsSL "$KEA_KEY_URL" | gpg --dearmor -o /usr/share/keyrings/isc-kea.gpg \
 && fpr="$(gpg --show-keys --with-colons /usr/share/keyrings/isc-kea.gpg | awk -F: '/^fpr/{print $10; exit}')" \
 && [ "$fpr" = "$KEA_KEY_FINGERPRINT" ] || { echo "Kea repository key $fpr is not the pinned $KEA_KEY_FINGERPRINT" >&2; exit 1; } \
 && echo "deb [signed-by=/usr/share/keyrings/isc-kea.gpg] $KEA_REPO $KEA_SUITE main" > /etc/apt/sources.list.d/isc-kea.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends "isc-kea-common=$KEA_VERSION" "isc-kea-dhcp4=$KEA_VERSION" \
    "isc-kea-dhcp-ddns=$KEA_VERSION" "isc-kea-hooks=$KEA_VERSION" \
 && apt-get purge -y curl gpg && apt-get autoremove -y \
 # ISC's package makes the daemons 0750 _kea: root with every capability
 # dropped (no DAC override) and fabric's DDNS user could not execute them.
 && chmod 0755 /usr/sbin/kea-dhcp4 /usr/sbin/kea-dhcp-ddns /usr/sbin/kea-lfc \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -o -g "$KEA_GID" fabrickea \
 && useradd -o -r -M -u "$KEA_UID" -g "$KEA_GID" -d /nonexistent -s /usr/sbin/nologin fabrickea \
 && mkdir -p /run/kea /var/lib/kea

ENTRYPOINT ["/usr/bin/tini", "--"]
