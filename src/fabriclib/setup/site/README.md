# fabriclib/setup/site

Guided on a new install, in the browser (manual 1.3.6). Root runs Guided's real questions here and owns the code, the port
and the certificate; the unprivileged listener in [listener/](listener/README.md) only serves the pages.

| File | What |
|---|---|
| `guided_site.py` | `GuidedSite`: the site from open to close, as `common/ask`'s front end and `hand_over`'s follower |
| `session_keeper.py` | `SessionKeeper`: the one-time code, its wrong tries and the one session it opens |
| `listener_link.py` | `ListenerLink`: the listener process and the socket pair to it |
| `start_listener.py` | Start the listener as `nobody`, with its socket, link and certificate as inherited descriptors |
| `tee_log.py` | `TeeLog`: the run's log, to the terminal and the page together |
| `site_wanted.py` | Whether this run is a Guided one the site serves |
| `constants.py` | The ports, limits, record and firewall comment |
| `port_holder.py` | What holds a port, for the message when it is taken |
| `pick_port.py` | Bind 8443 or the next free port up to 8453 |
| `host_addresses.py` | The addresses a person can reach this host on |
| `new_code.py` | A new one-time code |
| `make_certificate.py` | The temporary self-signed certificate, its key never on a disk |
| `certificate_fingerprint.py` | A certificate's SHA-256 fingerprint |
| `mint_site_cert.py` | The finish's certificate, from fabric's new CA |
| `site_rule.py` | The ufw rule for the site's port |
| `open_site_port.py` | Ask about the firewall, on the terminal, and open the port |
| `keep_site_port.py` | Keep the port open through setup's own firewall step |
| `close_site_port.py` | Remove what the site opened, by the rule's comment |
| `write_port_record.py` | Record the port for the firewall step |
| `read_port_record.py` | Read that record |
| `take_snapshot.py` | The install folder before the questions |
| `restore_snapshot.py` | Put it back when the run stops before Proceed |
| `question_view.py` | One question as the page shows it |
| `print_site_start.py` | The terminal's URL, code and fingerprint |
| `read_site_files.py` | The templates and static files, read as root for the listener |
| `finish_data.py` | What the finish page shows |
| `finish_guides.py` | The trust and DNS commands, copies of manual 4.3.6.2 and 4.3.6.3 |
| `check_console.py` | Root's half of the finish's check: the console's name and answer |
