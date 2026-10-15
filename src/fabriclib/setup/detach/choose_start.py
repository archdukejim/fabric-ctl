def choose_start(running, record, steps, start_over=False):
    """Purpose: what a full `sudo fabricctl setup` does first (decision 2.1.2.26, manual 1.3.2.3): follow the run
             still going, resume the last run that did not finish, or ask the questions and start a new one.
    Inputs:  running — whether fabric-setup.service runs now (unit_running); record — the last run's record
             (read_run) or None; steps — every step name in order (STEPS); start_over — --restart, --file or --join
             was given (new answers: the questions again).
    Returns: (what, remaining): ("attach", []) while the unit runs, whatever else is given; ("resume", [step, ...])
             when the record's run is "running" (its process died) or "failed" and steps remain — the steps not yet
             done, in STEPS order (so a step a newer release added is not skipped); otherwise ("new", list(steps)).
    Fails:   never — pure.
    Feeds:   setup/run_setup."""
    if running:
        return "attach", []
    if start_over or not record or record.get("state") not in ("running", "failed"):
        return "new", list(steps)
    done = set(record.get("done") or [])
    remaining = [s for s in steps if s not in done]
    return ("resume", remaining) if remaining else ("new", list(steps))
