# fabriclib/pki/common

Helpers shared by the manual PKI operations.

| File | What |
|---|---|
| `openssl.py` | Run openssl with stdin data; failures become a `ValidationError` with openssl's first error line |
| `to_pem.py` | Pasted/uploaded PEM, DER or bare base64 → list of PEM blocks of one kind (cert, CSR, key) |
| `describe_cert.py` | Subject, issuer, serial, SANs, key, validity, usages, CA flag, SHA-256 fingerprint of a PEM certificate |
| `ca_files.py` | Paths of the Step-CA root and intermediate certificates |
| `ca_path_len.py` | A CA certificate's path length (how many CA levels it may still sign) |
| `ca_parents_pem.py` | A nested site's parent CAs (empty for the root site and flat sites) |
| `ca_chain_pem.py` | Intermediate (+ a nested site's parent CAs) + root as one PEM bundle |
| `valid_days.py` | Validate a requested validity against `pki_manual_max_days` (default 1825) |
| `record_issued.py` | Append a manually issued certificate (never its key) to the issued-certificate ledger |
| `run_step.py` | Run the step CLI from the pinned Step-CA image as the step user, CA data (or another directory) at `/home/step`, no network |
| `artifacts_dir.py` | The step user's scratch directory `stepca/data/artifacts` (created 0750) |
| `valid_san.py` | Classify a subject alternative name as DNS / IP / e-mail, or reject it |
| `safe_name.py` | Download file name from a certificate name |
| `revoked_serials.py` | The serials revoked so far; serials compared without colons or leading zeros |
| `crl_points.py` | The CRL distribution points a certificate names (a service certificate naming another is issued again, 1.5.1.6) |
| `cert_dates.py` | A certificate's validity (not before, not after) |
| `cert_names.py` | The DNS and IP names a certificate on disk holds (the landing certificate is issued again when they differ from its names, 2.1.4.8) |
