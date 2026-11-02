from fabriclib.common.errors import ValidationError


class ScanBusy(ValidationError):
    """Purpose: a scan refused only for now (decision 2.1.10.26's limits): another scan is running on the host, or the
             same subnet was scanned less than a minute ago. A person is told to try again; a request made through
             AD (2.1.10.38) stays pending for the serving site's next poll instead of being answered "refused".
    Inputs:  the message, as ValidationError's.
    Returns: an exception.
    Fails:   never.
    Feeds:   scan_subnet (raises it), scancontrol/run_scan_requests (catches it)."""
