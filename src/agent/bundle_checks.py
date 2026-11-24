import os
import threading

from fabriclib.backup.check_bundle import check_bundle
from fabriclib.common.errors import ValidationError


class BundleChecks:
    """Purpose: each bundle's SHA-256 check for the console's list (manual 1.3.7.9), made once per file, size and
             modified time, in a thread of its own: a large bundle takes seconds to hash, longer than a page waits.
    Feeds:   agent/get_backup."""

    def __init__(self, check=check_bundle):
        """Purpose: an empty store.
        Inputs:  check — check_bundle (tests give their own).
        Returns: None.
        Fails:   never.
        Feeds:   CHECKS."""
        self.lock = threading.Lock()
        self.done = {}
        self.check = check

    def _run(self, key, path):
        """Purpose: one check, its outcome kept.
        Inputs:  key — (path, size, mtime); path — the bundle.
        Returns: None.
        Fails:   never (the check's refusal is its outcome).
        Feeds:   of."""
        try:
            manifest = self.check(path)
            outcome = {"check": "whole", "opened_by": manifest.get("opened_by") or "",
                       "method": manifest.get("method") or ""}
        except (ValidationError, OSError) as exc:
            outcome = {"check": str(exc), "opened_by": "", "method": ""}
        with self.lock:
            self.done[key] = outcome

    def of(self, path):
        """Purpose: a bundle's check: kept, or started now.
        Inputs:  path — the bundle.
        Returns: {"check": "whole" | "checking" | why it is not whole, "opened_by", "method"}.
        Fails:   never (a file gone: "checking" until the next list leaves it out).
        Feeds:   agent/get_backup."""
        try:
            st = os.stat(path)
        except OSError:
            return {"check": "checking", "opened_by": "", "method": ""}
        key = (path, st.st_size, st.st_mtime_ns)
        with self.lock:
            if key in self.done:
                return dict(self.done[key])
            self.done[key] = {"check": "checking", "opened_by": "", "method": ""}
        threading.Thread(target=self._run, args=(key, path), daemon=True, name="bundle-check").start()
        return {"check": "checking", "opened_by": "", "method": ""}


CHECKS = BundleChecks()
