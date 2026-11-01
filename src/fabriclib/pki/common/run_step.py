import os
import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.common.one_off_labels import one_off_labels


def run_step(v, args, home=None):
    """Purpose: Run the step CLI from the pinned Step-CA image in a throwaway container, as the step user,
             with the CA data directory (or `home`) mounted at /home/step and no network.
    Inputs:  v — fabric vars: deploy_base_dir, service_users.step.uid / .gid, image_stepca (the pinned
             image); args — list of step arguments, paths as seen inside the container (passwords only as
             *-password-file paths, never values); home — a directory to mount at /home/step instead of
             <deploy_base_dir>/stepca/data (a joining site has no CA yet), default None.
    Returns: step's stdout (str).
    Fails:   ValidationError "step-ca refused: <last 300 characters of stderr/stdout>" on any non-zero exit
             (step or docker); KeyError on missing vars; FileNotFoundError if docker is not installed.
    Feeds:   mint_offline_cert, sign_csr, sign_site_ca, make_site_ca_request (with home).
    Notes:   the CA keys never leave the host and the signing container has no network (--network none).
    """
    data = home or os.path.join(v["deploy_base_dir"], "stepca", "data")
    uid, gid = (int(v["service_users"]["step"][k]) for k in ("uid", "gid"))
    res = subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", f"{data}:/home/step",
                          "--user", f"{uid}:{gid}", *one_off_labels(),
                          "--entrypoint", "/usr/local/bin/step", v["image_stepca"],
                          *args],
                         capture_output=True, text=True)
    if res.returncode != 0:
        raise ValidationError(f"step-ca refused: {(res.stderr or res.stdout).strip()[-300:]}")
    return res.stdout
