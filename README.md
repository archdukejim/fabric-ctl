# fabric-ctl

A simple, lightweight, open-source setup for the core of a small network — authoritative DNS, an internal PKI, a
directory, single sign-on, secrets and a secure management web UI — installed on the host it runs on (amd64 or
arm64, Raspberry Pi included) and secure by default.

## Who it is for

People running a home lab, a small office or several houses who want the services every network needs without
hand-wiring them: the names, certificates, accounts and access control of their own machines, kept on their own
hardware and working offline.

## What it does

`fabricctl` installs and runs these as hardened containers under systemd, and keeps them configured:

| Service | Purpose |
|---|---|
| BIND 9 | Authoritative DNS with RFC 2136 updates and DNS-over-HTTPS |
| nginx | HTTPS for every service, the CA certificates page |
| Step-CA | The internal PKI: root and intermediate CAs, service certificates, ACME |
| OpenBao | Secrets, unlocked at boot by a key file, USB stick, security key or HSM |
| Samba AD | The directory: people, groups, machines and devices in one domain; Windows and Linux machines join it |
| Keycloak | Single sign-on with TOTP, on the directory |
| fabric-ctl web control | The web control: every action through a fixed, permission-checked host API |
| DNS filter | A second BIND that filters ads, trackers and malware with AdGuard's lists (on by default) |
| Kea, FreeRADIUS, Fluent Bit *(optional)* | DHCP, 802.1X, log forwarding |

Several installs can join one **federation** of sites, each with its own DNS zone, intermediate CA and copy of the
directory. Nothing changes on the host outside fabric's own folders without a yes from you.

## Getting started

```bash
sudo apt install ./fabricctl_<version>_all.deb    # from a GitHub release
sudo fabricctl setup                               # shows the plan and asks before changing the host
```

From a git checkout: `sudo scripts/install-from-checkout.sh` builds the package, installs it and runs setup.
Unattended: `sudo fabricctl setup --file vars.yaml --non-interactive --yes --approve all`. Afterwards,
`fabricctl` and the web UI at `https://fabric-ctl.<your domain>` do the day-to-day work.

## Documentation

The manual is in [`docs/`](docs/README.md), in five volumes: systems and services, technologies and features,
operations, installation and upgrades, notes and troubleshooting. Start with
[installation (3.2, 3.3)](docs/volume_3_installation/3.2.1-requirements.md) and
[working with fabricctl (4.3)](docs/volume_4_operations/4.3.1-fabricctl.md).

## License

MIT ([LICENSE](LICENSE)); bundled third-party code is listed in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
