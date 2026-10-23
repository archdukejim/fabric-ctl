class ValidationError(ValueError):
    """Input was rejected. The message is safe to show to the user."""


class NotFound(ValidationError):
    """The one thing a read names is not there (a person, computer, group or grant: decision 2.1.8.21); fabric-agent
    answers 404 with the message, which is safe to show."""


class NotPublished(ValidationError):
    """A quick publish (dns/publish_zone_list) refused before it wrote anything: the caller rolls back its own change
    and has nothing to publish again."""
