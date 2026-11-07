import os

from fabriclib.pki.mint_cert import mint_cert
from fabriclib.setup.site.constants import MINTED_NAME


def mint_site_cert(ctx, addresses, console_name):
    """Purpose: the site's last certificate, from fabric's new CA (manual 1.3.6.6): it names the host's addresses and
             the console's name, which the finish's check reaches this site by. Its files are read and removed at
             once: the key lives in memory only, as the first one's did (1.3.6.3).
    Inputs:  ctx — SetupContext (mint_cert's); addresses — list of str, the host's addresses; console_name — str.
    Returns: (chain PEM, key PEM).
    Fails:   SetupError from mint_cert (the CA not answering); OSError reading the files.
    Feeds:   setup/site/finish_data."""
    crt, key = mint_cert(ctx, addresses[0], [*addresses[1:], console_name], MINTED_NAME)
    try:
        with open(crt) as f:
            chain = f.read()
        with open(key) as f:
            private = f.read()
    finally:
        for path in (crt, key):
            if os.path.exists(path):
                os.remove(path)
    return chain, private
