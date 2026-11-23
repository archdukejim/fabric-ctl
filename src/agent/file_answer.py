class FileAnswer:
    """Purpose: a GET route's answer that is a file, not JSON (manual 1.3.3.1: a bundle's download): the handler streams
             it as application/octet-stream instead of replying with JSON.
    Feeds:   agent/get_backup (made), agent/handler (streamed)."""

    def __init__(self, path, name):
        """Purpose: the file to send.
        Inputs:  path — its path on the host; name — the file name the download is saved as.
        Returns: None.
        Fails:   never.
        Feeds:   agent/get_backup."""
        self.path, self.name = path, name
