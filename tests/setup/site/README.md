# tests/setup/site

Web-guided setup (manual 1.3.6.8), with a real listener process, real TLS and sockets, and Guided's real questions.

| File | What |
|---|---|
| `site_test.py` | In the `consent` suite: the site's trust, refusals and limits: wrong code and lockout, a second browser, a stale CSRF token, a wrong `Origin`, bad answers, declined consent, the idle limit, Cancel, a dead listener, port collisions |
| `flow_test.py` | In the `consent` suite: from Proceed to Finish with a stood-in run: progress, a dropped connection, a failed step, Ctrl-C and SIGHUP, the new certificate, the finish's check (the trust failure with real TLS) and the clean-up |
| `guides_test.py` | In the `consent` suite: the finish's commands, filled in, are the same as manual 4.3.6.2 and 4.3.6.3 |
| `check_console_test.py` | In the `consent` suite: the host's half of the finish's check against a real DNS answer and a real TLS console: right, wrong address, no answer, another CA's certificate |
| `listener_link_test.py` | In the `consent` suite: what root does with a listener that misbehaves: a line that is no message, an endless line, a listener that stops reading; and that a stop ends it at once |
| `browser_test.py` | In the `webui` suite: the same flow in a real Chromium (the project's pinned test image), at 1366 and 375 px; `SITE_PICTURES` keeps its screenshots |
| `site_probe.py` | Drives that Chromium over its DevTools pipe; compares the fingerprint before going past the warning |
| `preview.py` | Runs the site with stood-in data, to look at by hand |
| `signal_driver.py` | A process `flow_test.py` sends signals to |
| `support.py` | What these tests share |
