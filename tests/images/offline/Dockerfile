# A disposable host for the offline install test (tests/images/offline.sh, manual 1.14.4): Ubuntu 24.04 with
# systemd as PID 1, like the sandbox's (tests/sandbox/Dockerfile), and nothing fabric installs: no Docker, no
# fabricctl, none of its packages, and no apt lists. The bundle brings all of it (1.14.4.10, 3.14.2.2). It is built
# with network; the test then runs it on a network with no way out.
FROM ubuntu:24.04
ENV container=docker DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv dbus iproute2 iptables ca-certificates curl \
    sudo python3 procps kmod \
 && rm -rf /var/lib/apt/lists/* \
 && systemctl mask systemd-logind getty.target console-getty.service \
    systemd-binfmt.service proc-sys-fs-binfmt_misc.automount \
 && systemctl set-default multi-user.target
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
