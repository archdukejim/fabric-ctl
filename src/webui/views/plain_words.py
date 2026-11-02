import datetime
import re

# " (1.14.3.4)", " (manual 4.6.6)", " (2.3.6.2.6, 1.6.13.4)": a manual's numbers in brackets, with the space before
_NUMBERS = re.compile(r"\s*\((?:manual |see )?\d+(?:\.\d+)+(?:(?:, | and )\d+(?:\.\d+)+)*\)")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def without_manual_numbers(text):
    """Purpose: Text for people without the manual's numbers in brackets (1.8.6.3's copy rule; 1.8.8.6): the CLI and
             the logs keep them, the console drops them. Jinja filter `plain`.
    Inputs:  text — str (None: "").
    Returns: str.
    Fails:   never.
    Feeds:   render_page (the filter); pattern.html's relaxations, the Overview's host changes."""
    return _NUMBERS.sub("", str(text or ""))


def when_written(value):
    """Purpose: A time as people write it, "3 Oct 2026, 09:12" (1.8.8.6), from an ISO 8601 text; the time's own
             offset is kept (no conversion). Jinja filter `written`.
    Inputs:  value — str such as "2026-10-03T09:12:40+00:00" (or "": nothing to say).
    Returns: str; the value unchanged when it is not ISO 8601.
    Fails:   never.
    Feeds:   render_page (the filter); the Overview's host changes."""
    try:
        t = datetime.datetime.fromisoformat(str(value))
    except ValueError:
        return str(value or "")
    return f"{t.day} {_MONTHS[t.month - 1]} {t.year}, {t:%H:%M}"
