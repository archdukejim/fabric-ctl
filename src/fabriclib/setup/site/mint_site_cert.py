import os

from fabriclib.pki.mint_cert import mint_cert
from fabriclib.setup.site.constants import MINTED_NAME


def mint_site_cert(ctx, addresses, console_name):
    """Purpose: the site's last certificate, from fabric's new CA (manual 1.3.6.6): it names the host's addresses and
             the console's name, which the finish's check reaches this site by. step writes the files; they are read
             and removed at once, also when minting fails part way, so afterwards the key is in memory only.
    Inputs:  ctx — SetupContext (mint_cert's); addresses — list of str, the host's addresses; console_name — str.
    Returns: (chain PEM, key PEM).
    Fails:   SetupError from mint_cert (the CA not answering); OSError reading the files.
    Feeds:   setup/site/finish_data."""
    try:
        crt, key = mint_cert(ctx, addresses[0], [*addresses[1:], console_name], MINTED_NAME)
        with open(crt) as f:
            chain = f.read()
        with open(key) as f:
            private = f.read()
    finally:
        for extension in ("crt", "key"):
            path = ctx.path("stepca", "data", "artifacts", f"{MINTED_NAME}.{extension}")
            if os.path.exists(path):
                os.remove(path)
    return chain, private
