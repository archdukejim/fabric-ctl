# fabriclib/dns/common

Helpers shared by the DNS files (manual [1.4.2](../../../../docs/volume_1_description_and_architecture/1.4.2-landing-links.md#1421-landing-page-links-link-varsyaml)).

| File | What |
|---|---|
| `landing_link.py` | A record's landing-page link (label, port, path) checked from a form, or None when it is not linked |
| `fabric_record.py` | Whether a record of the site's zone is one fabric adds on every render (its service and setting), or None |
| `own_names.py` | The names fabric adds to the site's zone on every render, each with its service and setting |
| `drop_previous_own.py` | The site's zone without the names the last render added as fabric's own (`dns_fabric_own`), so a move or a rename leaves no old address or name (1.4.1.8) |
| `landing_names.py` | The landing page's names: the host's own name, `<domain>` and the zone's aliases of the host (nginx's server names, the certificate's names; 2.1.4.8, 1.4.2.6) |
| `zone_records.py` | The records of given types in a zone file as fabric renders it or BIND writes it, owners made absolute |
