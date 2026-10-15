class ValidationError(ValueError):
    """Input was rejected. The message is safe to show to the user."""


class NotPublished(ValidationError):
    """A quick publish (dns/publish_zone_list) refused before it wrote anything: the caller rolls back its own change
    and has nothing to publish again."""
