import os

from fabriclib.common.ensure_dir import ensure_dir
from fabriclib.common.write_file_if_changed import write_file_if_changed

# fabric's BIND image links Samba's DLZ module here, whatever the architecture (packaging/images/bind9)
MODULE = "/usr/lib/fabric/dlz_bind9.so"
# where BIND sees the DC's DNS partition and keytab (the DC's smb.conf names /data/bind-dns: the same path)
BIND_DNS = "/data/bind-dns"
OFF = "// the Windows domain is not provisioned yet: nothing to load (manual 1.6.5.6)\n"


def write_bind_dlz(v):
    """Purpose: what BIND includes for the AD zone (manual 1.6.5.6, 1.4.1.2): Samba's DLZ module serving the zone from
             the DC's database, and the keytab that verifies members' signed (GSS-TSIG) updates. Only once the domain
             is provisioned and its DNS database is there: before, the files are comments, so BIND starts without the
             DC. An online bundle's restore brings the marker back before the DC's databases, which load just before
             Samba starts (manual 1.3.7.6; found by the sandbox, 2026-11-23).
    Inputs:  v — rendered vars: deploy_base_dir. Reads <deploy_base>/samba/data/.fabric-provisioned and
             bind-dns/dns/sam.ldb.
    Returns: True if a file changed (BIND must restart to load or unload the module).
    Fails:   OSError creating the folder or writing.
    Feeds:   samba/deploy_samba (every apply), setup/start_services and deploy/restart_changed (after the domain is
             converged: the first provisioning turns it on).
    Notes:   <deploy_base>/samba/bind is mounted read-only at /etc/bind-samba; named.conf includes dlz.conf at the top
             level and options.conf inside options {}. No secret: the keytab stays in the DC's folder."""
    base = os.path.join(v["deploy_base_dir"], "samba")
    folder = os.path.join(base, "bind")
    ensure_dir(folder, 0o755, 0, 0)
    on = (os.path.exists(os.path.join(base, "data", ".fabric-provisioned"))
          and os.path.exists(os.path.join(base, "data", "bind-dns", "dns", "sam.ldb")))
    dlz = (f'dlz "AD DNS Zone" {{\n    database "dlopen {MODULE} --url={BIND_DNS}/dns/sam.ldb";\n}};\n'
           if on else OFF)
    options = f'tkey-gssapi-keytab "{BIND_DNS}/dns.keytab";\n' if on else OFF
    changed = write_file_if_changed(os.path.join(folder, "dlz.conf"), dlz, 0o644)
    changed |= write_file_if_changed(os.path.join(folder, "options.conf"), options, 0o644)
    return changed
