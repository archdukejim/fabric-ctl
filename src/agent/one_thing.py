import re

from fabriclib.common.errors import NotFound, ValidationError

# the refusals of a read of one thing that say it is not there (fabric's own words, from the DC's operations and
# fabriclib): "no group x in the domain", "no machine ws1 in the domain", "no grant x"; and run_op's own "no such
# entry" (the DC has no such person), said as "no <named>"
MISSING = re.compile(r"^no (person|group|machine|grant) \S+( in .*)?$")
NO_ENTRY = "no such entry"


def one_thing(read, *args, named=""):
    """Purpose: A read of one person, computer, group or grant (decision 2.1.8.21): its refusal that the thing is not
             there becomes NotFound (404); any other refusal stays a ValidationError (400: the DC not running).
    Inputs:  read — the fabriclib read; args — its arguments; named — what it reads, for run_op's "no such entry"
             ("person bob": the 404 says "no person bob").
    Returns: the read's answer.
    Fails:   NotFound for a thing that is not there; the read's other errors unchanged.
    Feeds:   agent/get_route (groups/<name>, people/<uid>, machines/<name>, domain/grants/<name>)."""
    try:
        return read(*args)
    except NotFound:
        raise
    except ValidationError as exc:
        if MISSING.match(str(exc)):
            raise NotFound(str(exc)) from exc
        if named and str(exc) == NO_ENTRY:
            raise NotFound(f"no {named}") from exc
        raise
