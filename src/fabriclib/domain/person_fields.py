import re

from fabriclib.common.errors import ValidationError
from fabriclib.directory.create_person import MAIL_RE

# a person's fields fabric edits (manual 1.6.12.4, 2.1.6.93): the request's name -> AD's standard attribute
FIELDS = {"first": "givenName", "last": "sn", "name": "displayName", "email": "mail", "phone": "telephoneNumber",
          "mobile": "mobile", "title": "title", "department": "department", "company": "company",
          "office": "physicalDeliveryOfficeName", "city": "l", "state": "st", "country": "c", "manager": "manager",
          "employee_id": "employeeID"}
NAME_RE = re.compile(r"^[\w .,'-]{1,64}$")
DISPLAY_RE = re.compile(r"^[\w .,'()-]{1,64}$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9 ()./-]{2,31}$")
TEXT_RE = re.compile(r"^[^\x00-\x1f\x7f<>\"\\;]{1,64}$")
COUNTRY_RE = re.compile(r"^[A-Za-z]{2}$")
UID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
EMPLOYEE_RE = re.compile(r"^[\w./-]{1,16}$")
KEPT = ("first", "last", "name")        # never cleared: Keycloak and the console show them
WHY = {
    "first": "first name: letters and simple punctuation (space . , ' -), 1-64",
    "last": "last name: letters and simple punctuation (space . , ' -), 1-64",
    "name": "display name: letters, digits and simple punctuation, 1-64",
    "email": "e-mail address looks wrong",
    "phone": "phone: digits, an optional leading +, spaces and ( ) . / -, 3-32",
    "mobile": "mobile: digits, an optional leading +, spaces and ( ) . / -, 3-32",
    "country": "country: a two-letter code (ISO 3166-1, e.g. GB or US)",
    "manager": "manager: a person's user name",
    "employee_id": "employee ID: letters, digits and . / - _, 1-16",
}
CHECK = {"first": NAME_RE, "last": NAME_RE, "name": DISPLAY_RE, "email": MAIL_RE, "phone": PHONE_RE,
         "mobile": PHONE_RE, "country": COUNTRY_RE, "manager": UID_RE, "employee_id": EMPLOYEE_RE}


def read_person_fields(uid, given):
    """Purpose: a person's edit, checked before anything is asked of the DC (2.1.6.93): only the fields given, each
             trimmed; an empty value clears it, except the first, last and display names, which are never cleared;
             the country upper-cased.
    Inputs:  uid — the person edited (a manager is never themselves); given — {field: str} from the route's body or
             the command's options.
    Returns: {field: str} in FIELDS' order.
    Fails:   ValidationError: "give at least one of a person's fields: …", "unknown field: …", "<field> must be
             text", WHY's message for a value refused, "<label>: up to 64 characters, without quotes, backslashes, ;
             or <>", "manager: not the person themselves", "<label> may not be cleared".
    Feeds:   domain/edit_person."""
    unknown = sorted(set(given) - set(FIELDS))
    if unknown:
        raise ValidationError(f"unknown field: {', '.join(unknown)} (a person's fields: {', '.join(FIELDS)})")
    if not given:
        raise ValidationError(f"give at least one of a person's fields: {', '.join(FIELDS)}")
    out = {}
    for field in FIELDS:
        if field not in given:
            continue
        value = given[field]
        if not isinstance(value, str):
            raise ValidationError(f"{field} must be text")
        value = value.strip()
        label = field.replace("_", " ")
        if not value:
            if field in KEPT:
                raise ValidationError(f"{WHY[field].split(':')[0]} may not be cleared")
            out[field] = ""
            continue
        rule = CHECK.get(field, TEXT_RE)
        if not rule.match(value):
            raise ValidationError(WHY.get(field)
                                  or f"{label}: up to 64 characters, without quotes, backslashes, ; or <>")
        if field == "manager" and value.lower() == uid.lower():
            raise ValidationError("manager: not the person themselves")
        out[field] = value.upper() if field == "country" else value
    return out
