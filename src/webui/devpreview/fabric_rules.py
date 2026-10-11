"""fabriclib's real rules when the dev preview runs from a checkout (devserver.py puts src on the path); the
webui image carries only src/webui/, so without them the preview shows sample data and skips the directory forms."""
from webui import views

try:
    from fabriclib.common.errors import ValidationError  # noqa: F401
    from fabriclib.dns.constants import PRIVATE_TLDS  # noqa: F401
    from fabriclib.dns.ptr_for_ip import ptr_for_ip  # noqa: F401
    from fabriclib.dns.reverse_zones import reverse_zones  # noqa: F401
    from fabriclib.directory.common.check_device_fields import check_device_fields  # noqa: F401
    from fabriclib.directory.common.check_role_fields import check_role_fields  # noqa: F401
    from fabriclib.directory.constants import DEVICE_NAME_RE, DEVICE_TYPES, PERMISSIONS, ROLE_NAME_RE  # noqa: F401
    from fabriclib.directory.list_devices import list_devices  # noqa: F401
    from fabriclib.rbac.permissions import BUNDLES, PERMISSIONS as FABRIC_PERMISSIONS  # noqa: F401
except ImportError:
    ValidationError = ValueError
    ptr_for_ip = reverse_zones = list_devices = check_device_fields = check_role_fields = None
    DEVICE_NAME_RE = ROLE_NAME_RE = None
    PRIVATE_TLDS = ()                       # without fabriclib every name counts as public in the preview
    DEVICE_TYPES, PERMISSIONS = [], {}
    BUNDLES, FABRIC_PERMISSIONS = {}, {p: "" for p in views.PREVIEW_PERMS}
