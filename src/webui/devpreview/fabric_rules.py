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
    from fabriclib.samba.check_kerberos_policy import check_kerberos_policy  # noqa: F401
    from fabriclib.samba.check_password_policy import check_password_policy  # noqa: F401
    from fabriclib.samba.read_policy_changes import read_policy_changes  # noqa: F401
except ImportError:
    ValidationError = ValueError
    ptr_for_ip = reverse_zones = list_devices = check_device_fields = check_role_fields = None
    check_password_policy = read_policy_changes = check_kerberos_policy = None
    DEVICE_NAME_RE = ROLE_NAME_RE = None
    PRIVATE_TLDS = ()                       # without fabriclib every name counts as public in the preview
    DEVICE_TYPES, PERMISSIONS = [], {}
    BUNDLES, FABRIC_PERMISSIONS = {}, {p: "" for p in views.PREVIEW_PERMS}
try:                                       # the address manager's pure views (1.10.4.40)
    from fabriclib.ipam.common.option_codes import CATALOGUE  # noqa: F401
    from fabriclib.ipam.common.site_plan import site_plan  # noqa: F401
    from fabriclib.ipam.export_plan import export_plan  # noqa: F401
    from fabriclib.ipam.networks_view import networks_view  # noqa: F401
    from fabriclib.ipam.options.effective_options import effective_options  # noqa: F401
    from fabriclib.ipam.options.settings_options import settings_options  # noqa: F401
    from fabriclib.ipam.suggestions import suggest_split, suggest_subnet  # noqa: F401
    from fabriclib.ipam.rules.check_cut_off import check_cut_off  # noqa: F401
    from fabriclib.ipam.rules.check_rule import check_rule  # noqa: F401
    from fabriclib.ipam.rules.effective_rules import effective_rules  # noqa: F401
    from fabriclib.ipam.rules.rule_networks import rule_networks  # noqa: F401
    from fabriclib.ipam.rules.rule_number import rule_number  # noqa: F401
    from fabriclib.ipam.rules.rules_view import rules_view  # noqa: F401
except ImportError:
    CATALOGUE = {}
    site_plan = export_plan = networks_view = effective_options = settings_options = None
    suggest_split = suggest_subnet = None
    check_cut_off = check_rule = effective_rules = rule_networks = rule_number = rules_view = None
try:
    from fabriclib.rbac.required_permission import required_permission  # noqa: F401
except ImportError:
    required_permission = None
