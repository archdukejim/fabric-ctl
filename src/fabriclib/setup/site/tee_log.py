import io


class TeeLog(io.TextIOBase):
    """The run's log, to the terminal and the page together; a terminal that has gone stops nothing (1.3.6.5)."""

    def __init__(self, site):
        """Purpose: remember the site.
        Inputs:  site — GuidedSite.
        Returns: None.
        Fails:   never.
        Feeds:   setup/site/guided_site."""
        super().__init__()
        self.site = site

    def write(self, text):
        """Purpose: pass one chunk on, to the terminal and the page.
        Inputs:  text — str.
        Returns: its length.
        Fails:   never: a dead terminal or a dead page is left out.
        Feeds:   follow_run."""
        self.site.say(text)
        self.site.keep_log(text)
        return len(text)
