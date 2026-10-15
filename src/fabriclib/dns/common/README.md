# fabriclib/dns/common

Helpers shared by the DNS files (manual [1.4.2](../../../../docs/volume_1_description_and_architecture/1.4.2-landing-links.md#1421-landing-page-links-link-varsyaml)).

| File | What |
|---|---|
| `landing_link.py` | A record's landing-page link (label, port, path) checked from a form, or None when it is not linked |
| `fabric_record.py` | Whether a record of the site's zone is one fabric adds on every render (its service and setting), or None |
| `landing_names.py` | The landing page's names: the host's own name, `<domain>` and the zone's aliases of the host (nginx's server names, the certificate's names; 2.1.4.8, 1.4.2.6) |
