"""The Enterprise Admin and break glass (manual 1.6.12.2, 1.6.13.6; decisions 2.1.6.68, 2.1.6.69, 2.1.6.75)."""
import string

ENTERPRISE_ADMIN = "fabric-admin"           # the Enterprise Admin's account: always this name (2.1.6.69)
PASSWORD_LENGTH = 24                        # fabric makes 24 characters (2.1.6.69: at least 14)
# the special characters safe everywhere the password may be pasted or stored: a shell, YAML, an .ini file, LDAP,
# Samba, Keycloak (2.1.6.69); never a quote, backslash, $, backtick, !, %, #, ;, &, |, <, >, /, braces, brackets, *, ?
# or space
SAFE_SPECIALS = "-_.,:+=@^~"
CLASSES = (string.ascii_uppercase, string.ascii_lowercase, string.digits, SAFE_SPECIALS)
FOLDER = "fabric-admin"                     # in the home of the account that ran sudo, beside the recovery keys
FILE_NAME = "fabric-admin-password.txt"
RECORD = "break-glass.json"                 # <config>/break-glass.json: where the file was written (never the password)
