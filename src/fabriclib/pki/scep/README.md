# fabriclib/pki/scep

Enrolling phones, tablets and laptops (manual 1.5.3; decision 2.1.5.12): Step-CA's SCEP provisioner with
one-time challenges, Apple configuration profiles, PKCS#12 files for Android, and the webhook Step-CA calls.

| File | What |
|---|---|
| `constants.py` | The provisioner's name, ports, hook paths, the challenge store, the RA's files and limits |
| `enrol_apple.py` | An Apple profile for one device: a one-time challenge made for the person, the profile around it |
| `enrol_p12.py` | A PKCS#12 for one Android (or other) device: key, certificate and chain; the password shown once; AES by default, 3DES for Android 11 and older |
| `create_challenge.py` | A one-time challenge: random, short-lived, for one name, bound to its maker; only its hash kept |
| `check_challenge.py` | Step-CA's SCEPCHALLENGE question: spent on first use; refused when unknown, used, withdrawn, expired or for another name |
| `record_scep_issue.py` | Step-CA's NOTIFYING call: the certificate into the ledger as its maker's, linked to its device |
| `answer_hook.py` | The hook's answer: only Step-CA's own client certificate is answered; challenge or notification |
| `make_mobileconfig.py` | The Apple profile: root CA, SCEP, Wi-Fi and wired 802.1X EAP-TLS payloads |
| `list_enrolments.py` | Open profiles and certificates issued by enrolment, for the console |
| `withdraw_challenge.py` | Withdraw an unused profile's challenge (its maker, or `pki:revoke`) |
| `ensure_scep_ra.py` | The provisioner's RSA decrypter key and certificate, made per install, renewed under 90 days |
| `configure_scep_provisioner.py` | The provisioner, its webhooks and the plain-HTTP listener in Step-CA's ca.json |
| `deploy_scep_hook.py` | The hook's systemd unit and socket folder, with the web console |
| `check_scep_settings.py` | `scep_challenge_minutes` and `scep_cert_days`, checked at every apply |
| `common/` | Helpers shared by the files above (see its README) |
| `__init__.py` | Package marker (empty) |
