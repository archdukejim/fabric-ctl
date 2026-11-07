# fabriclib/setup/site/listener

The setup site's listener (manual 1.3.6.3): a separate process, run as `nobody` with `python3 -I` and the standard library
only. It holds no power: it serves pages and passes what people type to root, which judges it.

| File | What |
|---|---|
| `site_main.py` | The process's entry: takes its descriptors, drops what it can, serves |
| `site_state.py` | What the listener knows: the current question, phase, log and session |
| `control_link.py` | Its end of the socket pair to root |
| `build_tls.py` | The TLS context, from the memory file; notes the name a browser asked for |
| `site_server.py` | The HTTPS server |
| `request_base.py` | `RequestBase`: headers, refusals, the Origin check, the session and CSRF token |
| `request_handler.py` | `RequestHandler`: the routes (the `ROUTES` table is what the entry-point inventory reads) |
| `page_for.py` | Which page this phase shows |
| `render_page.py` | One page from its template |
| `notes_html.py` | What setup printed, as the page's notes |
| `finish_html.py` | The finish's trust and DNS sections |
| `check_verdict.py` | What the finish's check found, in words |
