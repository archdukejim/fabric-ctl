import secrets

from fabriclib.breakglass.constants import CLASSES, PASSWORD_LENGTH


def break_glass_password(length=PASSWORD_LENGTH):
    """Purpose: a new password for `fabric-admin`, the break-glass account (2.1.6.69): random, from the operating
             system's CSPRNG, of upper and lower case letters, digits and only the special characters safe in a shell,
             YAML, an .ini file, LDAP, Samba and Keycloak (constants.SAFE_SPECIALS), each class at least once.
    Inputs:  length — int, at least 14 (default 24).
    Returns: str of `length` characters.
    Fails:   ValueError for a length under 14.
    Feeds:   breakglass/ensure_enterprise_admin (setup), breakglass/reset_break_glass."""
    if length < 14:
        raise ValueError("the break-glass password has at least 14 characters (2.1.6.69)")
    alphabet = "".join(CLASSES)
    chars = [secrets.choice(c) for c in CLASSES] + [secrets.choice(alphabet) for _ in range(length - len(CLASSES))]
    for i in range(len(chars) - 1, 0, -1):          # the guaranteed characters at random places
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)
