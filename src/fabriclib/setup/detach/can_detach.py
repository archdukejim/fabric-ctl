import os
import shutil


def can_detach(booted="/run/systemd/system"):
    """Purpose: whether setup's work can run as its own systemd unit on this host (decision 2.1.2.26).
    Inputs:  booted — the directory systemd creates when it is the host's init (sd_booted's test; tests give their
             own).
    Returns: True when the host was booted with systemd and systemd-run is on PATH.
    Fails:   never.
    Feeds:   detach/hand_over (otherwise the steps run in the session, said so)."""
    return os.path.isdir(booted) and shutil.which("systemd-run") is not None
