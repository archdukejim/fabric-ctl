# Volume 2 — Engineering decisions

Why fabric is the way it is, in three parts: 2.1 the decision register (Rule 13), 2.2 troubleshooting, 2.3 engineering notes. Each follows Volume 1's chapters: 2.1.C, 2.2.C and 2.3.C are about chapter 1.C.

## 2.1 Decisions

One decision per topic: what was decided, the chapters it shapes, when and by whom, why, and its status (in force, revised, replaced or removed). Recorded decisions are rules for this repository; one whose status is **Open** waits for the owner — ask before building around it. Old decision numbers (D1–D121, F, J, S) are resolved in 2.3.1.1.

- [2.1.1 Decisions: The product, and how it is built and released](2.1.1-product.md)
- [2.1.2 Decisions: Architecture and the host](2.1.2-architecture.md)
- [2.1.3 Decisions: fabricctl, setup and fabric-agent](2.1.3-fabricctl.md)
- [2.1.4 Decisions: DNS: BIND](2.1.4-dns.md)
- [2.1.5 Decisions: Certificates: Step-CA](2.1.5-certificates.md)
- [2.1.6 Decisions: Identity: the directory and sign-in](2.1.6-identity.md)
- [2.1.7 Decisions: Secrets: OpenBao](2.1.7-openbao.md)
- [2.1.8 Decisions: The web UI](2.1.8-webui.md)
- [2.1.9 Decisions: Federation](2.1.9-federation.md)
- [2.1.10 Decisions: DHCP: Kea](2.1.10-dhcp.md)
- [2.1.11 Decisions: 802.1X: FreeRADIUS](2.1.11-radius.md)
- [2.1.12 Decisions: The DNS filter](2.1.12-dns-filter.md)
- [2.1.13 Decisions: Time: chrony](2.1.13-time.md)
- [2.1.14 Decisions: Container images](2.1.14-images.md)
- [2.1.15 Decisions: Log forwarding: Fluent Bit](2.1.15-logs.md)
- [2.1.16 Decisions: Disk encryption](2.1.16-disk-encryption.md)

Nothing yet for 2.1.17 (it follows chapter 1.17).

## 2.2 Troubleshooting

Symptoms, causes and fixes.

- [2.2.6 Keycloak and the directory](2.2.6-keycloak-gotchas.md)
- [2.2.8 The web UI](2.2.8-webui-troubleshooting.md)

Nothing yet for 2.2.1, 2.2.2, 2.2.3, 2.2.4, 2.2.5, 2.2.7, 2.2.9, 2.2.10, 2.2.11, 2.2.12, 2.2.13, 2.2.14, 2.2.15, 2.2.16, 2.2.17 (they follow chapters 1.1, 1.2, 1.3, 1.4, 1.5, 1.7, 1.9, 1.10, 1.11, 1.12, 1.13, 1.14, 1.15, 1.16, 1.17).

## 2.3 Engineering notes

Trade-offs, blockers, investigations, test results and history.

- [2.3.1 Notes: The product, and how it is built and released](2.3.1-product-notes.md)
- [2.3.2 Notes: Architecture and the host](2.3.2-architecture-notes.md)
- [2.3.4 Notes: DNS: BIND](2.3.4-dns-notes.md)
- [2.3.5 Notes: Certificates: Step-CA](2.3.5-certificate-notes.md)
- [2.3.6 Notes: Identity: the directory and sign-in](2.3.6-identity-notes.md)
- [2.3.7 Notes: Secrets: OpenBao](2.3.7-openbao-notes.md)
- [2.3.8 Notes: The web UI](2.3.8-webui-notes.md)
- [2.3.9 Notes: Federation](2.3.9-federation-notes.md)
- [2.3.10 Notes: DHCP: Kea](2.3.10-dhcp-notes.md)
- [2.3.11 Notes: 802.1X: FreeRADIUS](2.3.11-radius-notes.md)
- [2.3.12 Notes: The DNS filter](2.3.12-dns-filter-notes.md)
- [2.3.14 Notes: Container images](2.3.14-image-notes.md)

Nothing yet for 2.3.3, 2.3.13, 2.3.15, 2.3.16, 2.3.17 (they follow chapters 1.3, 1.13, 1.15, 1.16, 1.17).

## Assets

[`assets/`](assets/README.md): data the chapters rest on (the review ledger).
