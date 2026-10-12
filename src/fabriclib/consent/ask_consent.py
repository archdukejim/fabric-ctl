import datetime
import os

from fabriclib.common.ask import ask
from fabriclib.common.console import BOLD, NC, YELLOW, heading
from fabriclib.consent.carry_over_splits import carry_over_splits
from fabriclib.consent.groups import GROUPS
from fabriclib.consent.load_consent import load_consent
from fabriclib.consent.save_consent import save_consent
from fabriclib.setup.errors import SetupError


def _parse(names):
    """Purpose: group names from --approve / --decline values ("firewall,accounts", repeatable).
    Inputs:  names — list of str (None: none).
    Returns: set of group names ("all" kept as it is).
    Fails:   SetupError for an unknown group name.
    Feeds:   ask_consent."""
    out = {n.strip() for item in (names or []) for n in item.split(",") if n.strip()}
    unknown = out - set(GROUPS) - {"all"}
    if unknown:
        raise SetupError(f"unknown host-change group(s): {', '.join(sorted(unknown))} "
                         f"(groups: {', '.join(GROUPS)}, or all)")
    return out


def _ask(group, changes, new):
    """Purpose: one question: what this group changes, what saying no means, and a y/n answer (no default: an
             answer must be typed).
    Inputs:  group — group name; changes — every planned change; new — the ones not approved before.
    Returns: True for yes, False for no.
    Fails:   EOFError from input() when stdin is closed.
    Feeds:   ask_consent."""
    g = GROUPS[group]
    print(f"\n  {BOLD}{g['title']}{NC} ({g['level']})")
    for c in changes:
        print(f"    {'+' if c in new and len(new) < len(changes) else '-'} {c}")
    print(f"    {YELLOW}If no: {g['declined']}.{NC}")
    while True:
        answer = ask(f"consent.{group}", "    Allow these changes? [y/n] ").lower()
        if answer in ("y", "yes", "n", "no"):
            return answer.startswith("y")


def ask_consent(config_dir, plan, interactive, approve=None, decline=None, stops=()):
    """Purpose: get an answer for every host change setup is about to make, before the first step (manual 1.2.9.4): one
                question per group, asked again only for changes not approved before.
    Inputs:  config_dir — the install's config folder (consent.yaml); plan — {group: [change, ...]} from
             plan_host_changes; interactive — False for --non-interactive (never asks); approve, decline — the
             --approve / --decline values (group names, comma-separated, or "all" for approve); they override
             earlier answers; stops — groups whose "no" stops setup on this host though they are recommended (the
             ports while ufw is on, 2.1.2.12). An earlier "no" that would stop setup (those, and required or choice
             groups) is asked again in an interactive run, so a person is never stuck with it. Env SUDO_USER/USER
             (recorded as who answered).
    Returns: {group: "yes"|"no"|"skipped"} for the groups in plan ("skipped": not asked, a group it needs was
             declined or skipped; nothing recorded for it). consent.yaml records each answer with the changes it
             covers (a yes keeps what was approved before too, so a later run that changes less still matches).
    Fails:   SetupError: an unknown group name; a non-interactive run with groups that have no answer (names
             them and the flag); a required or choice group answered no (says what that means). Answers given
             before the failure are saved.
    Feeds:   setup/run_setup."""
    approve, decline = _parse(approve), _parse(decline)
    if "all" in decline:
        raise SetupError("--decline takes group names, not all")
    groups = load_consent(config_dir) or {}
    carried = carry_over_splits(groups, plan)
    if carried:
        print(f"  {', '.join(carried)}: answered as before this release split the question they came from")
    if plan:
        heading("Changes to this host outside fabric's own folders — each needs your yes")
    pending, answers = [], {}
    now = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    who = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
    for group, changes in plan.items():
        needs = GROUPS[group].get("needs")
        if needs in plan and answers.get(needs) in ("no", "skipped"):   # not asked once what it needs is declined
            answers[group] = "skipped"                                    # (2.1.2.13); nor what needs this one
            continue
        rec = groups.get(group) or {}
        new = [c for c in changes if c not in (rec.get("changes") or [])]
        if group in decline:
            yes = False
        elif group in approve or "all" in approve:
            yes = True
        elif rec.get("answer") in ("yes", "no") and not new and not (
                interactive and rec["answer"] == "no" and (GROUPS[group]["level"] != "recommended" or group in stops)):
            answers[group] = rec["answer"]      # a "no" that would stop setup is asked again when someone is there
            continue
        elif not interactive:
            pending.append(group)
            continue
        else:
            yes = _ask(group, changes, new)
        kept = (rec.get("changes") or []) if rec.get("answer") == "yes" and yes else []
        groups[group] = {"answer": "yes" if yes else "no", "changes": kept + [c for c in changes if c not in kept],
                         "when": now, "by": who}
        answers[group] = groups[group]["answer"]
    save_consent(config_dir, groups)
    if pending:
        raise SetupError("these changes to the host need an answer: " + ", ".join(pending)
                         + ". Run setup interactively, or pass --approve " + ",".join(pending)
                         + " (or --approve all) / --decline GROUP")
    refused = [g for g, a in answers.items() if a == "no" and GROUPS[g]["level"] != "recommended"]
    if refused:
        raise SetupError("; ".join(f"{GROUPS[g]['title']} declined: {GROUPS[g]['declined']}" for g in refused))
    return answers
