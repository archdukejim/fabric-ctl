def fake_job(state, kind, result):
    """Purpose: A background job, done at once in the preview.
    Inputs:  state — DevState; kind — "doctor", "images", "settings", "backup", "restore"; result — its result.
    Returns: {"id"}.
    Fails:   never.
    Feeds:   fake_misc, fake_backup."""
    jobs = state.data.setdefault("jobs", {})
    job_id = f"dev-{len(jobs) + 1}"
    jobs[job_id] = {"id": job_id, "kind": kind, "state": "done", "error": "", "result": result}
    return {"id": job_id}
