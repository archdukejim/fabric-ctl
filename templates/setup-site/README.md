# templates/setup-site

The pages of web-guided setup's temporary site (manual 1.3.6), `string.Template` files filled by
`fabriclib/setup/site/listener/`. Setup hands them to the listener over its control link; installed at
`fabric/lib/setup-site/`, with `static/setup-site/`.

| File | What |
|---|---|
| `base.html` | The frame of every page: the steps, the temporary certificate's notice, the script |
| `code.html` | The first page: the fingerprint to compare and the one-time code |
| `question.html` | One of Guided's questions, with what setup printed before it (a refusal among it) |
| `plan.html` | The plan and its one confirmation |
| `working.html` | While setup works on an answer; reloads by itself |
| `progress.html` | The run's log, live |
| `failed.html` | A step failed: why, the log, how to resume |
| `restarting.html` | Before the site moves to fabric's own certificate: its fingerprint |
| `finish.html` | Trust, DNS, the check, onward |
| `closed.html` | The site has closed, and why |
| `refused.html` | A request refused, saying why |
