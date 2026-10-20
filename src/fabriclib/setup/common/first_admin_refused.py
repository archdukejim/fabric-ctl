import re

from fabriclib.directory.person_name_refused import person_name_refused

NAME_RE = re.compile(r"^[\w .,'-]{1,60}$")
MAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,}$")
# the first Directory Administrator's settings (2.1.6.69), with what each is
KEYS = {"webui_admin_user": "user name", "webui_admin_first_name": "first name",
        "webui_admin_last_name": "last name", "webui_admin_email": "e-mail address"}
OPTIONAL = ("webui_admin_email",)          # 2.1.6.93: data on record when given, never required


def first_admin_refused(key, value):
    """Purpose: why one of the first Directory Administrator's answers is refused (2.1.6.69, 2.1.6.93): a user name
             that is not one (person_name_refused: fabric's names and `fabric-admin` included), an empty first or last
             name or one of other than letters and simple punctuation (60 at most), an e-mail address that is not
             one. The user name and both names are required; the e-mail address may be left empty.
    Inputs:  key — webui_admin_user, webui_admin_first_name, webui_admin_last_name or webui_admin_email; value — the
             answer (str or None).
    Returns: None when it is taken; otherwise why not (str).
    Fails:   KeyError for another key.
    Feeds:   setup/ask_first_admin, setup/common/valid_setting."""
    value = str(value or "").strip()
    if not value:
        return None if key in OPTIONAL else f"the first administrator's {KEYS[key]} is required"
    if key == "webui_admin_user":
        return person_name_refused(value)
    if key != "webui_admin_email":
        return None if NAME_RE.match(value) else f"a {KEYS[key]}: letters and simple punctuation, at most 60 characters"
    return None if MAIL_RE.match(value) else f"{value!r} is not an e-mail address"
