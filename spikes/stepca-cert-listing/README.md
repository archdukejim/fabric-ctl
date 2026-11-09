# stepca-cert-listing

Prototype for 2.1.5.13: how fabric lists the certificates Step-CA issues itself (ACME, SCEP, an 802.1X member's
machine certificate at its join). The question, the options and what done means are in the manual,
[2.3.5.5](../../docs/volume_2_engineering_decisions/2.3.5-certificate-notes.md#2355-prototype-listing-the-certificates-step-ca-issues-itself-planned).

Throwaway (global Rule 4): never merged into `src/`. Not written or run yet: it runs the real Step-CA image, and local
runs wait for the build VM `g23-vm-dev-1`.
