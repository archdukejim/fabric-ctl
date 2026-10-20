import paths


def remove_device(samdb, lp, site, name):
    """Purpose: a device removed from the domain's OU=devices (its roles go with it: they are the device's own
             attribute).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); name — the device's name.
    Returns: {"name"}.
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT, ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "remove_device")."""
    samdb.delete(f"CN={name},{paths.folder_dn(samdb, 'devices')}")
    return {"name": name}
