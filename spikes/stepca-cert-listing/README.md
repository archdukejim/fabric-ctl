# stepca-cert-listing

Prototype for 2.1.5.13: how fabric lists the certificates Step-CA issues itself (ACME, SCEP, an 802.1X member's
machine certificate at its join). The question, the options and what done means are in the manual,
[2.3.5.5](../../docs/volume_2_engineering_decisions/2.3.5-certificate-notes.md#2355-prototype-listing-the-certificates-step-ca-issues-itself).

Throwaway (global Rule 4): never merged into `src/`. Run on the build VM `g23-vm-dev-1` on 2026-11-09; the outcome is
in 2.3.5.5.

    sudo python3 spikes/stepca-cert-listing/run.py     (Docker, root, network for the Go module)

`run.py` makes a CA as `tests/pki/acme.py` does, issues one certificate over ACME and one over JWK, and reads Step-CA's
database with `reader/` (Go, `smallstep/nosql`) live, from a copy, stopped and after a restart, and checks its log.
