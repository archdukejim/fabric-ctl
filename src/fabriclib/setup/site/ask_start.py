from fabriclib.common.ask import ask


def ask_start():
    """Purpose: the setup site's first choice (manual 1.3.7.10): a new install, Guided's questions as before, or
             Restore from a backup. On the site it is two buttons (question_view); at a terminal attached to it, n or r.
    Inputs:  none.
    Returns: "new" or "restore".
    Fails:   never for a bad answer: it is said, and asked again.
    Feeds:   setup/run_setup (once the site is open)."""
    while True:
        answer = ask("setup.start", "[N]ew install, or [R]estore from a backup? [n]: ", "n").strip().lower()
        if answer in ("n", "new"):
            return "new"
        if answer in ("r", "restore"):
            return "restore"
        print(f"  {answer!r}: n for a new install, r to restore from a backup")
