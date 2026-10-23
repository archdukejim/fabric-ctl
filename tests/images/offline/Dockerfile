# A disposable host for the offline install test (tests/images/offline.sh, manual 1.14.4): Ubuntu 24.04 with
# systemd as PID 1, like the sandbox's (tests/sandbox/Dockerfile), and the Ubuntu packages fabric installs
# already there: the bundle does not carry them yet (2.3.14.3), so this image stands in for a host that has them.
# It is built with network; the test then runs it on a network with no way out.
FROM ubuntu:24.04
ENV container=docker DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv dbus iproute2 iptables ca-certificates curl \
    sudo python3 procps kmod \
    python3-yaml python3-jinja2 python3-bcrypt chrony openssl ufw dnsutils \
    docker.io docker-compose-v2 docker-buildx \
    sssd-ad sssd-tools libnss-sss libpam-sss libsss-sudo krb5-user libsasl2-modules-gssapi-mit adcli \
 && rm -rf /var/lib/apt/lists/* \
 && systemctl mask systemd-logind getty.target console-getty.service \
    systemd-binfmt.service proc-sys-fs-binfmt_misc.automount \
 && systemctl set-default multi-user.target
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
