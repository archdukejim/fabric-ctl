import os

from fabriclib.common.service_user import service_user
from fabriclib.vault.ssh.constants import PUBLISHED


def publish_ssh_ca(v, public_key, name=PUBLISHED):
    """Purpose: publish an SSH CA's public key where managed machines fetch it over HTTPS (manual 1.6.11.9.4: the user
             CA; 1.6.11.9.9: the host CA), or withdraw it: a machine that gets 404 stops trusting the CA.
    Inputs:  v — settings: deploy_base_dir, service_users (nginx); public_key — the CA's key line, or "" to withdraw;
             name — the file in /certs/: PUBLISHED (the user CA, the default) or HOST_PUBLISHED (the host CA).
    Returns: True when the published file changed (written or removed).
    Fails:   OSError writing or removing.
    Feeds:   vault/ssh/set_ssh_certificates, setup/setup_openbao."""
    path = os.path.join(v["deploy_base_dir"], "nginx", "www", "certs", name)
    if not public_key:
        if os.path.exists(path):
            os.remove(path)
            return True
        return False
    text = public_key.strip() + "\n"
    if os.path.exists(path):
        with open(path) as f:
            if f.read() == text:
                return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".new", "w") as f:
        f.write(text)
    uid, gid = service_user(v, "nginx")
    os.chown(path + ".new", uid, gid)
    os.chmod(path + ".new", 0o644)
    os.replace(path + ".new", path)
    return True
