"""Well-known paths, derived from where fabric is installed
(<deploy_base>/fabric/lib/fabriclib/common/paths.py)."""
import os

LIB_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FABRIC_DIR = os.path.dirname(LIB_DIR)
# setup, reinstall, uninstall and restore run from the package's read-only copy (src/ux/cli/fabricctl): the install's
# config and records are still the install's, never next to that copy (dpkg would leave them behind on purge)
PACKAGE_DIR = "/usr/lib/fabricctl/fabric"
INSTALL_DIR = "/opt/fabric" if FABRIC_DIR == PACKAGE_DIR else FABRIC_DIR
DEPLOY_BASE_DIR = os.path.dirname(INSTALL_DIR)
VARS_FILE = os.path.join(INSTALL_DIR, "config", "vars.yaml")
VARS_LOCK_FILE = os.path.join(INSTALL_DIR, "config", ".vars.lock")
# held shared by every apply and by a change an apply follows; the plan poll runs only when it can hold it alone
APPLY_INTENT_FILE = os.path.join(INSTALL_DIR, "config", ".apply.intent")     # 2.1.10.45
SECRETS_FILE = os.path.join(INSTALL_DIR, "config", "fabric-secrets.yml")
AUDIT_FILE = os.path.join(INSTALL_DIR, "archive", "audit.log")
ISSUED_CERTS_FILE = os.path.join(INSTALL_DIR, "archive", "issued-certs.jsonl")
REVOKED_CERTS_FILE = os.path.join(INSTALL_DIR, "archive", "revoked-certs.jsonl")   # 2.1.5.10
CERT_RENEWAL_FILE = os.path.join(INSTALL_DIR, "archive", "cert-renewal.json")   # the last run (2.1.5.4)
DB_ROTATION_FILE = os.path.join(INSTALL_DIR, "archive", "db-rotation.json")    # the last run (2.1.7.4)
FEDERATION_FILE = os.path.join(INSTALL_DIR, "config", "federation.yaml")
FEDERATION_LOCK_FILE = os.path.join(INSTALL_DIR, "config", ".federation.lock")
BIND_DATA_DIR = os.path.join(DEPLOY_BASE_DIR, "bind9", "data")
