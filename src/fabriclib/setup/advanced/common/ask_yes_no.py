from fabriclib.common.ask import ask
from fabriclib.common.console import NC, YELLOW


def ask_yes_no(qid, question, now):
    """Purpose: one yes/no item of the menu (manual 1.2.9.11.3): [Y/n] or [y/N], the current value the default.
    Inputs:  qid — the question's ID (setup.part.<name>, setup.consent.<group>, setup.host_join_domain); question — the
             text before the brackets; now — the current value (bool). Interactive.
    Returns: bool, the answer (Enter: now). An answer other than y, yes, n or no is refused, saying so, and asked again.
    Fails:   EOFError from input().
    Feeds:   setup/advanced (the parts, the host changes, domain membership)."""
    while True:
        answer = ask(qid, f"\n  {question}? {'[Y/n]' if now else '[y/N]'} ", "y" if now else "n").lower()
        if answer in ("y", "yes", "n", "no"):
            return answer.startswith("y")
        print(f"    {YELLOW}{answer!r}: answer y or n{NC}")
