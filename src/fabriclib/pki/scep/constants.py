"""Names, paths and limits of device enrolment (manual 1.5.3; decision 2.1.5.12)."""
import os
import re

from fabriclib.common.paths import INSTALL_DIR

PROVISIONER = "fabric-scep"                 # Step-CA's SCEP provisioner: http://<hostname_stepca>/scep/fabric-scep
INSECURE_PORT = 9080                        # Step-CA's plain-HTTP listener inside fabric_net (insecureAddress)
CHALLENGE_PATH = "/hooks/scep/challenge"    # the SCEPCHALLENGE webhook, on the web console's name
ISSUED_PATH = "/hooks/scep/issued"          # the NOTIFYING webhook
CHALLENGES_FILE = os.path.join(INSTALL_DIR, "archive", "scep-challenges.json")    # root 0600: hashes, never challenges
CHALLENGES_LOCK = os.path.join(INSTALL_DIR, "archive", ".scep-challenges.lock")
RA_CERT = "scep_ra.crt"                     # in Step-CA's certs/: the RSA decrypter's certificate
RA_KEY = "scep_ra_key"                      # in Step-CA's secrets/: its key, encrypted with scep_ra_password
RA_BITS = 3072
RA_DAYS = 730
RA_RENEW_DAYS = 90                          # issued again by setup when fewer days are left
DEFAULT_MINUTES = 60                        # scep_challenge_minutes
MIN_MINUTES, MAX_MINUTES = 5, 1440
DEFAULT_CERT_DAYS = 365                     # scep_cert_days
P12_KEY_BITS = 2048                         # what every Android version and most supplicants take
NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")    # a device-style label: the certificate's CN
STEPCA_OWN_NAMES = ("DNS:localhost", "IP Address:127.0.0.1")       # in Step-CA's own TLS certificate, no service's
ENROL_KINDS = ("scep", "enrol-p12")         # ledger kinds of certificates from enrolment
