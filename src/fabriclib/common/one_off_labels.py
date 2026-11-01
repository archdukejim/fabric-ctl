def one_off_labels():
    """Purpose: the `docker run` arguments that keep a throwaway container out of every Compose project (manual
             1.2.4.6): an image fabric builds with `docker compose build` carries Compose's project and service
             labels, a container run from it inherits them, and the project's `docker compose up
             --abort-on-container-exit` (every fabric unit) then takes it for one of its own and stops the whole
             service when it exits (the lab's dhcp campaign, 2026-10-31: each Kea config check restarted Kea).
             The labels are set to a project no unit runs.
    Inputs:  none.
    Returns: list of str, to put before the image in a `docker run` command.
    Fails:   never.
    Feeds:   dhcp/check_kea_config, pki/common/run_step, setup/init_pki."""
    return ["--label", "com.docker.compose.project=fabric-one-off", "--label", "com.docker.compose.service=one-off",
            "--label", "com.docker.compose.oneoff=True"]
