import re

from fabriclib.directory.person_name_refused import person_name_refused

NAME_RE = re.compile(r"^[\w .,'-]{1,60}$")
MAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,}$")
# the first Directory Administrator's settings (2.1.6.69), with what each is
KEYS = {"webui_admin_user": "user name", "webui_admin_name": "full name", "webui_admin_email": "e-mail address"}


def first_admin_refused(key, value):
    """Purpose: why one of the first Directory Administrator's answers is refused (2.1.6.69): a user name that is not
             one (person_name_refused: fabric's names and `fabric-admin` included), an empty full name or one of
             other than letters and simple punctuation (60 at most), an e-mail address that is not one. All three are
             required.
    Inputs:  key — webui_admin_user, webui_admin_name or webui_admin_email; value — the answer (str or None).
    Returns: None when it is taken; otherwise why not (str).
    Fails:   KeyError for another key.
    Feeds:   setup/ask_first_admin, setup/common/valid_setting."""
    value = str(value or "").strip()
    if not value:
        return f"the first administrator's {KEYS[key]} is required"
    if key == "webui_admin_user":
        return person_name_refused(value)
    if key == "webui_admin_name":
        return None if NAME_RE.match(value) else "a full name: letters and simple punctuation, at most 60 characters"
    return None if MAIL_RE.match(value) else f"{value!r} is not an e-mail address"
