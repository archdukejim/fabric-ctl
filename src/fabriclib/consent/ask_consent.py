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


def _ask_all(asks, plan, groups):
    """Purpose: the one question for every host change that needs an answer when no plan was shown (a `--step` run, or
             --yes with someone there; manual 1.2.9.11.5): each group with its changes and what saying no means, then
             one y/n answer for all of them (no default: an answer must be typed).
    Inputs:  asks — the groups to ask about, in order; plan — {group: [change, ...]}; groups — consent.yaml's groups
             (a change not approved before is marked "+").
    Returns: True for yes, False for no.
    Fails:   EOFError from input() when stdin is closed.
    Feeds:   ask_consent."""
    for group in asks:
        g, rec = GROUPS[group], groups.get(group) or {}
        new = [c for c in plan[group] if c not in (rec.get("changes") or [])]
        print(f"\n  {BOLD}{g['title']}{NC} ({g['level']})")
        for c in plan[group]:
            print(f"    {'+' if c in new and len(new) < len(plan[group]) else '-'} {c}")
        print(f"    {YELLOW}If no: {g['declined']}.{NC}")
    while True:
        answer = ask("consent.step", "\n  Allow these changes? [y/n] ").lower()
        if answer in ("y", "yes", "n", "no"):
            return answer.startswith("y")


def ask_consent(config_dir, plan, interactive, approve=None, decline=None, stops=(), decided=None):
    """Purpose: get an answer for every host change setup is about to make, before the first step (manual 1.2.9.4,
             1.2.9.11): from the plan's one yes (decided), from --approve / --decline, from earlier answers, or — when
             no plan was shown and someone is there — one question for all that need one.
    Inputs:  config_dir — the install's config folder (consent.yaml); plan — {group: [change, ...]} from
             plan_host_changes; interactive — False for --non-interactive (never asks); approve, decline — the
             --approve / --decline values (group names, comma-separated, or "all" for approve); they override
             earlier answers; stops — groups whose "no" stops setup on this host though they are recommended (the
             ports while ufw is on, 2.1.2.12); decided — {group: bool} from the plan's Proceed (choose_plan: every
             group allowed, those turned off in the menu declined), or None. Without decided, an earlier "no" that
             would stop setup (those, and required or choice groups) is asked again in an interactive run, so a person
             is never stuck with it. Env SUDO_USER/USER (recorded as who answered).
    Returns: {group: "yes"|"no"|"skipped"} for the groups in plan ("skipped": a group it needs was declined or
             skipped; nothing recorded for it). consent.yaml records each answer with the changes it covers (a yes
             keeps what was approved before too, so a later run that changes less still matches).
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
    prov, answers = {}, {}
    now = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    who = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
    for group, changes in plan.items():
        needs = GROUPS[group].get("needs")
        if needs in plan and prov.get(needs) in ("no", "skipped", "kept-no"):   # not made once what it needs is
            prov[group] = "skipped"                                              # declined (2.1.2.13)
            continue
        rec = groups.get(group) or {}
        new = [c for c in changes if c not in (rec.get("changes") or [])]
        if group in decline:
            prov[group] = "no"
        elif group in approve or "all" in approve:
            prov[group] = "yes"
        elif decided is not None:
            prov[group] = "yes" if decided.get(group) else "no"
        elif rec.get("answer") in ("yes", "no") and not new and not (
                interactive and rec["answer"] == "no" and (GROUPS[group]["level"] != "recommended" or group in stops)):
            prov[group] = "kept-" + rec["answer"]   # a "no" that would stop setup is asked again when someone is there
        else:
            prov[group] = "ask" if interactive else "pending"
    asks = [g for g, p in prov.items() if p == "ask"]
    yes_all = False
    if asks:
        heading("Changes to this host outside fabric's own folders — they need your yes")
        yes_all = _ask_all(asks, plan, groups)
    pending = [g for g, p in prov.items() if p == "pending"]
    for group, changes in plan.items():
        needs, p = GROUPS[group].get("needs"), prov[group]
        if p == "skipped" or (needs in plan and answers.get(needs) in ("no", "skipped")):
            answers[group] = "skipped"
            continue
        if p == "pending":
            continue
        rec = groups.get(group) or {}
        if p.startswith("kept-"):
            answers[group] = rec["answer"]
            continue
        yes = p == "yes" or (p == "ask" and yes_all)
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
