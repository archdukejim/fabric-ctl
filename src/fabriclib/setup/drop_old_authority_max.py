from fabriclib.common.errors import ValidationError
from fabriclib.pki.check_cert_lifetimes import authority_max_hours, given_authority_hours

OLD_SERVICE_DAYS = 47       # cert_service_days' default, which the old value was made from when it was not set


def drop_old_authority_max(data):
    """Purpose: the upgrade step of 2.1.5.14.3: take out a stepca_cert_max_lifetime_hours that fabric wrote itself,
             so Step-CA's maximum is worked out from the lifetimes; a value an administrator set is kept, and refused
             later when it is shorter than they need (pki/check_cert_lifetimes). Acts only on positive evidence: the
             value is exactly what fabric before 0.10.0 wrote when it was not set (cert_service_days × 24 hours,
             1128h with the default), or exactly what the lifetimes work out to now (fabric's own value, the same
             maximum either way).
    Inputs:  data — settings (an existing install's vars, or a settings file given to setup; modified in place).
    Returns: the change description (str), or None when nothing was taken out: the setting absent (a fresh install, or
             one already upgraded), or set to any other value.
    Fails:   never: a value that is not whole hours, or lifetimes that are not whole days, are left for
             check_cert_lifetimes to refuse with its message.
    Feeds:   setup/upgrade_vars (an existing install), setup/collect_vars (a settings file of an older fabric)."""
    try:
        given = given_authority_hours(data)
        service = data.get("cert_service_days", OLD_SERVICE_DAYS)
        old = int(service) * 24 if str(service).strip().isdigit() else None
        worked_out = int(authority_max_hours(data)[:-1])
    except ValidationError:
        return None
    if given is None or given not in (old, worked_out):
        return None
    del data["stepca_cert_max_lifetime_hours"]
    return (f"stepca_cert_max_lifetime_hours: {given}h was fabric's own value, taken out: Step-CA's maximum is now "
            f"worked out from the lifetimes ({worked_out}h, 2.1.5.14.3)")
