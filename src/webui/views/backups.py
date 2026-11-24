from webui.views.render_page import render_page


def backups(ctx, overview, restore="", section="", signin_old=False, whole=False):
    """Purpose: the Backups page (manual 1.3.7.9): the bundles with their checks and Download, Back up now, the schedule
             with its runs, and Restore: a bundle picked, then one section, then its warning in full with the key and
             the site's name to type, or the whole bundle with its warning; Upload a bundle; the last whole restore
             from the console (whether it runs, the end of its log).
    Inputs:  ctx — page context; overview — backup_overview(); restore — the bundle picked to restore ("" none, or
             one not in the list: none); section — the section picked ("": none yet, or not one of the bundle's);
             signin_old — True when the last sign-in is older than the 5 minutes a change needs (said up front);
             whole — True: the picked bundle's whole restore, its warning and form.
    Returns: HTML str.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/backups_page, devserver."""
    bundles = overview.get("bundles") or []
    picked = next((b for b in bundles if b["file"] == restore), None)
    sections = {s["name"]: s for s in overview.get("sections") or []}
    chosen = sections.get(section) if picked and section in (picked.get("sections") or []) else None
    return render_page("backups", ctx=ctx, page="/settings/backups", ov=overview, bundles=bundles, picked=picked,
                       parts=sections, chosen=chosen, signin_old=signin_old, whole=bool(whole and picked),
                       same_version=bool(picked) and picked.get("fabric_version") == overview.get("version"))
