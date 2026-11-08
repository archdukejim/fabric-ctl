def note_kept(ctx, answer, read, back):
    """Purpose: A page drawn from kept data says so (manual 1.8.9.4): what the frame's line and Refresh need.
    Inputs:  ctx — page context; answer — the agent's answer (its "kept" is there only when it was served from what was
             kept); read — the agent route, for Refresh; back — the page's own path, to come back to.
    Returns: answer, unchanged; ctx["kept"] set when the answer was kept.
    Fails:   never.
    Feeds:   the page routes of the reads fabric-agent keeps."""
    kept = answer.get("kept") if isinstance(answer, dict) else None
    if kept:
        ctx["kept"] = {**kept, "read": read, "back": back}
    return answer
