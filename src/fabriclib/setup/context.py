import os
from dataclasses import dataclass, field

import yaml

from fabriclib.common.paths import FABRIC_DIR


@dataclass
class SetupContext:
    """Everything a setup step needs. `source_dir` is the fabric/ tree the
    code runs from (a git checkout or an installed copy); the install lives
    under `deploy_base` (default /opt)."""
    deploy_base: str = "/opt"
    source_dir: str = FABRIC_DIR
    user_vars_file: str = None
    offline: bool = False
    non_interactive: bool = False
    assume_yes: bool = False
    join_invitation: str = None                   # setup --join: the upstream's invitation
    vars: dict = field(default_factory=dict)      # rendered vars (after deploy)
    _secrets: dict = None                         # loaded on first use (see secrets)
    restart_services: set = field(default_factory=set)   # certs/config changed this run
    force_certs: bool = False                     # re-issue service certs even if current
    cert_problems: list = field(default_factory=list)   # what a certificate run reported but did not raise (2.1.4.8)
    admin_password_file: str = None               # setup --admin-password-file (unattended, 2.1.6.33)
    admin_password: str = None                    # the first admin's chosen password: memory only, never saved
    fresh_install: bool = False                   # no settings yet and no domain provisioned (collect_vars)
    host_choices: dict = field(default_factory=dict)   # recommended host changes on/off, the menu's (1.2.9.11.3)
    origins: dict = field(default_factory=dict)   # settings the menu shows as "found" or "default", not chosen

    @property
    def target_dir(self):
        """Purpose: the installed fabric tree.
        Inputs:  none (reads self.deploy_base).
        Returns: "<deploy_base>/fabric" (str).
        Fails:   never — string join only.
        Feeds:   config_dir, stage_source, deploy_config (CLI wrapper), configure_firewall and start_services
                 (the installed lib/)."""
        return os.path.join(self.deploy_base, "fabric")

    @property
    def config_dir(self):
        """Purpose: the install's configuration folder.
        Inputs:  none (reads self.target_dir).
        Returns: "<deploy_base>/fabric/config" (str).
        Fails:   never — string join only.
        Feeds:   vars_file, secrets_file, collect_vars and deploy_config (fabric.yaml, link-vars.yaml)."""
        return os.path.join(self.target_dir, "config")

    @property
    def vars_file(self):
        """Purpose: path of the rendered vars (written by the deploy step).
        Inputs:  none (reads self.config_dir).
        Returns: "<deploy_base>/fabric/config/vars.yaml" (str).
        Fails:   never — string join only.
        Feeds:   load_state, collect_vars (is this an existing install?), configure_firewall, start_services,
                 run_restore_command (refuses while it exists)."""
        return os.path.join(self.config_dir, "vars.yaml")

    @property
    def secrets_file(self):
        """Purpose: path of fabric's own secrets file (0600; absent once imported into OpenBao).
        Inputs:  none (reads self.config_dir).
        Returns: "<deploy_base>/fabric/config/fabric-secrets.yml" (str).
        Fails:   never — string join only.
        Feeds:   secrets, cli main (`secrets`), collect_vars, deploy_config, setup_openbao, start_services,
                 backup_install, export_install."""
        return os.path.join(self.config_dir, "fabric-secrets.yml")

    def path(self, *parts):
        """Purpose: a path under the install root.
        Inputs:  parts — path components (str) below deploy_base, e.g. ("stepca", "data", "certs").
        Returns: os.path.join(deploy_base, *parts) (str).
        Fails:   never — string join only (TypeError if a part is not a str).
        Feeds:   most setup steps, uninstall, backup/export, pki.mint_cert."""
        return os.path.join(self.deploy_base, *parts)

    def load_state(self):
        """Purpose: read the rendered vars of the install; forget cached secrets so they are re-read.
        Inputs:  none (reads self.vars_file if it exists).
        Returns: self, with self.vars = the parsed vars.yaml (unchanged when the file is absent), and the
                 secrets cache cleared.
        Fails:   OSError if the file exists but cannot be read; yaml.YAMLError if it does not parse.
        Feeds:   run_setup (after deploy, for --step and doctor), cli main, renew_service_certs,
                 run_uninstall_command, uninstall, backup_install, deploy_config."""
        if os.path.exists(self.vars_file):
            with open(self.vars_file) as f:
                self.vars = yaml.safe_load(f) or {}
        self._secrets = None
        return self

    @property
    def secrets(self):
        """Purpose: fabric's own secrets, read on first use — from the file, or from OpenBao once imported —
                 so commands that never need them (status, uninstall, certificates) work while OpenBao is locked.
        Inputs:  none (reads self.secrets_file and self.vars; cached in self._secrets).
        Returns: dict of secret name -> value ({} when neither the file nor OpenBao has any).
        Fails:   ValidationError from load_secrets when the secrets live in OpenBao and it is unreachable or sealed;
                 yaml/OS errors reading the file.
        Feeds:   init_pki (ca_password), setup_openbao (openbao_oidc_secret), create_admin, verify_install."""
        if self._secrets is None:
            from fabriclib.secrets.load_secrets import load_secrets     # imports OpenBao client code
            self._secrets = load_secrets(self.secrets_file, self.vars or None)
        return self._secrets

    @secrets.setter
    def secrets(self, value):
        """Purpose: replace the cached secrets (setter of the `secrets` property).
        Inputs:  value — dict of secrets, or None to re-read on next use.
        Returns: None; self._secrets is set.
        Fails:   never — attribute assignment.
        Feeds:   — (no caller in the repository sets it today)."""
        self._secrets = value

    def uid(self, user):
        """Purpose: the uid and gid fabric expects for one service account.
        Inputs:  user — key in vars `service_users` (e.g. "nginx", "step", "ldap"); reads self.vars.
        Returns: (uid, gid) as ints; (0, 0) when the account is not in service_users.
        Fails:   ValueError/TypeError if the configured uid/gid is not a number.
        Feeds:   init_pki, start_bootstrap, mint_service_certs, verify_install, pki.mint_cert (file ownership)."""
        u = self.vars.get("service_users", {}).get(user, {})
        return int(u.get("uid", 0)), int(u.get("gid", 0))

    def enabled(self, flag, default=False):
        """Purpose: whether a boolean setting in the rendered vars is on.
        Inputs:  flag — top-level vars key; default — value when the key is absent (default False).
        Returns: bool(self.vars.get(flag, default)).
        Fails:   never — dict lookup only.
        Feeds:   — (no caller in the repository)."""
        return bool(self.vars.get(flag, default))
