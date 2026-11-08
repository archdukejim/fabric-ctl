import secrets

_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"     # none a person misreads: no 0/O, 1/I/L


def new_code():
    """Purpose: a random one-time code for the site (manual 1.3.6.3): printed on the terminal only, about 60 bits.
    Inputs:  none.
    Returns: str, three groups of four: "K7WX-93QF-TP2M".
    Fails:   never.
    Feeds:   setup/site/guided_site."""
    text = "".join(secrets.choice(_ALPHABET) for _ in range(12))
    return f"{text[:4]}-{text[4:8]}-{text[8:]}"
