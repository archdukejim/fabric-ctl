"""What a fabric-agent call can raise (src/ux/web/server.py turns each into a page)."""


class ValidationError(ValueError):
    """The agent rejected the input (HTTP 400); message is safe to show."""


class NotFound(ValidationError):
    """The one thing the call names is not there (HTTP 404, decision 2.1.8.21); message is safe to show."""


class AgentError(RuntimeError):
    """The agent is unreachable or failed."""


class AuthError(RuntimeError):
    """The agent did not accept the sign-in token (expired, ended): sign in again."""


class PermissionDenied(RuntimeError):
    """The signed-in person lacks the permission this needs; message is safe to show."""
