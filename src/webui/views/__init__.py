"""The pages of the web UI (Jinja2, autoescaped; templates in templates/webui-app, the stylesheet in
static/webui-app): one file per page, all importable from here (`from webui import views`)."""
from webui.views.constants import (NAV, PENDING_PAGES, FREERADIUS_SECTIONS, BIND9_SECTIONS, OPENBAO_SECTIONS,  # noqa: F401
                                   DNS_FILTER_SECTIONS,
                                   OPENBAO_VIEWS, SLOT_TYPES, DIRECTORY_SECTIONS, STEPCA_MENU, STEPCA_VIEWS, KEY_TYPES,
                                   TSIG_SCOPES, TSIG_ANY_TYPES, SERVICES, PREVIEW_PERMS, MENU_PERMS,
                                   WIZARD_STEPS, WIZARD_FIELDS)
from webui.views.apply_result import apply_result  # noqa: F401
from webui.views.audit import audit  # noqa: F401
from webui.views.bind9 import bind9  # noqa: F401
from webui.views.continue_page import continue_page  # noqa: F401
from webui.views.css import css  # noqa: F401
from webui.views.directory import directory  # noqa: F401
from webui.views.people import people  # noqa: F401
from webui.views.groups import groups  # noqa: F401
from webui.views.policies import policies  # noqa: F401
from webui.views.dns_filter import dns_filter  # noqa: F401
from webui.views.error_page import error_page  # noqa: F401
from webui.views.federation import federation  # noqa: F401
from webui.views.freeradius import freeradius  # noqa: F401
from webui.views.job_page import job_page  # noqa: F401
from webui.views.kea import kea  # noqa: F401
from webui.views.machine_result import machine_result  # noqa: F401
from webui.views.openbao import openbao  # noqa: F401
from webui.views.overview import overview  # noqa: F401
from webui.views.person_result import person_result  # noqa: F401
from webui.views.pki_result import pki_result  # noqa: F401
from webui.views.radius_secret import radius_secret  # noqa: F401
from webui.views.security import security  # noqa: F401
from webui.views.settings import settings  # noqa: F401
from webui.views.settings_plan import settings_plan  # noqa: F401
from webui.views.stepca import stepca  # noqa: F401
from webui.views.tsig_result import tsig_result  # noqa: F401
from webui.views.changes import changes  # noqa: F401
from webui.views.account import account  # noqa: F401
from webui.views.nav_menu import nav_menu  # noqa: F401
