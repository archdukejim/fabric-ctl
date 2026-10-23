def describe_import(result):
    """Purpose: the lines printed for an offline bundle's import (`fabricctl images import`, `setup --offline`).
    Inputs:  result — import_bundle's dict.
    Returns: list of str.
    Fails:   never.
    Feeds:   run_images_command, setup/import_offline_bundle."""
    lines = [f"{len(result['loaded'])} image(s) loaded, {len(result['present'])} already present",
             f"{len(result['verified'])} signature(s) of fabric's published images verified offline"]
    if result["unchecked"]:
        lines.append("not checked (image_signature_check: false, manual 1.14.3.4): " + ", ".join(result["unchecked"]))
    return lines
