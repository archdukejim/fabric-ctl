def describe_import(result):
    """Purpose: the lines printed for an offline bundle's import (`fabricctl images import`, `setup --offline`).
    Inputs:  result — import_bundle's dict.
    Returns: list of str; a relaxation (signatures not checked, images left out of the bundle, a .deb
             not checked) on a line of its own.
    Fails:   never.
    Feeds:   run_images_command, setup/import_offline_bundle."""
    lines = [f"{len(result['loaded'])} image(s) loaded, {len(result['present'])} already present",
             f"{len(result['verified'])} signature(s) of fabric's published images verified offline"]
    if result["unchecked"]:
        lines.append("relaxed: not checked (image_signature_check: false, manual 1.14.3.4): "
                     + ", ".join(result["unchecked"]))
    if result.get("left_out"):
        lines.append("relaxed: the bundle was exported with --allow-unpublished and leaves out "
                     + "; ".join(f"{k} ({why})" for k, why in result["left_out"].items())
                     + ": this host builds them, which needs the internet (2.1.14.21)")
    if result.get("deb_unchecked"):
        lines.append(f"relaxed: the bundle carries a fabricctl .deb given with --deb ({result['deb_unchecked']}), "
                     "not checked against fabric's signed apt repository (2.1.14.23)")
    return lines
