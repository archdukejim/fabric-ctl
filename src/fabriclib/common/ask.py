import getpass
import re

# "<area>.<name>": the area is fixed in the code; the rest may come from a key (a prompt asked in a loop over keys:
# "menu.vars.<key>"), so anything after the dot is accepted — the lint suite checks the literal part
QID_RE = re.compile(r"^[a-z][a-z0-9_]*\..", re.DOTALL)


_front_end = None       # None: the terminal. Otherwise an object with ask(qid, prompt, secret): web-guided setup


def use_front_end(front):
    """Purpose: send every question to another front end until told otherwise (web-guided setup's site, manual
             1.3.6.4), so its questions and checks stay the terminal's own and neither can drift.
    Inputs:  front — an object with ask(qid, prompt, secret) returning the answer as typed; None: the terminal.
    Returns: None.
    Fails:   never.
    Feeds:   setup/site/guided_site."""
    global _front_end
    _front_end = front


def _read(qid, prompt, secret=False):
    """Purpose: one answer as typed, from the front end in use or the terminal.
    Inputs:  qid — the question's stable ID; prompt — str; secret — True: not echoed on a terminal.
    Returns: the answer (str), unstripped.
    Fails:   EOFError / KeyboardInterrupt from input() or getpass; what the front end raises (closing the site).
    Feeds:   ask, ask_secret, ask_yes_no."""
    if _front_end is not None:
        return _front_end.ask(qid, prompt, secret)
    return getpass.getpass(prompt) if secret else input(prompt)


def _check(qid):
    """Purpose: refuse a question ID that is not "<area>.<name>" (the entry-point inventory lists questions by it,
             manual 1.1.5.6, 3.1.2.5).
    Inputs:  qid — the question's stable ID.
    Returns: None.
    Fails:   ValueError for an ID that is not a str of the form <area>.<name> (a coding error, never the user's).
    Feeds:   ask, ask_secret."""
    if not isinstance(qid, str) or not QID_RE.match(qid):
        raise ValueError(f"question ID {qid!r} is not <area>.<name> (manual 1.1.5.6)")


def ask(qid, prompt, default=None):
    """Purpose: ask a person one question on the terminal: the only place fabric reads an answer (manual 1.1.5.6).
             What the person sees is the prompt exactly as given.
    Inputs:  qid — the question's stable ID, "<area>.<name>" (e.g. "setup.ad_domain"; from the key for a prompt
             asked in a loop: "menu.vars.<key>"); prompt — str shown as input() shows it; default — returned when
             the answer is empty (None: the empty answer is returned).
    Returns: the answer with surrounding whitespace stripped, or default when it is empty and a default is given.
    Fails:   ValueError for a malformed qid; EOFError / KeyboardInterrupt from input() propagate unchanged.
    Feeds:   every interactive prompt in src/ (setup, the vars menu, consent, undo, fabricctl's commands)."""
    _check(qid)
    answer = _read(qid, prompt).strip()
    if not answer and default is not None:
        return default
    return answer


def ask_secret(qid, prompt):
    """Purpose: ask a person for a secret on the terminal without echoing it (getpass): the only place fabric reads
             one interactively (manual 1.1.5.6).
    Inputs:  qid — the question's stable ID, "<area>.<name>"; prompt — str shown as getpass shows it.
    Returns: the answer exactly as typed (not stripped: a secret is the caller's to trim).
    Fails:   ValueError for a malformed qid; EOFError / KeyboardInterrupt from getpass propagate unchanged.
    Feeds:   setup (first admin, join invitation), fabricctl's tsig, radius, logs and vault commands."""
    _check(qid)
    return _read(qid, prompt, secret=True)


def ask_yes_no(qid, question, now):
    """Purpose: ask a person one yes/no question on the terminal (manual 1.1.5.6): [Y/n] or [y/N], the current value
             the default.
    Inputs:  qid — the question's stable ID, "<area>.<name>" (e.g. "setup.part.<name>", "setup.consent.<group>");
             question — the text before the brackets; now — the current value (bool).
    Returns: bool, the answer (Enter: now). An answer other than y, yes, n or no is refused, saying so, and asked again.
    Fails:   ValueError for a malformed qid; EOFError / KeyboardInterrupt from input() propagate unchanged.
    Feeds:   setup/advanced (the parts, the host changes, domain membership)."""
    _check(qid)
    while True:
        answer = _read(qid, f"\n  {question}? {'[Y/n]' if now else '[y/N]'} ").strip().lower() or ("y" if now else "n")
        if answer in ("y", "yes", "n", "no"):
            return answer.startswith("y")
        print(f"    {answer!r}: answer y or n")
