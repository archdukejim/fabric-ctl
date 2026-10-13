# src/scephook

| File | What |
|---|---|
| `server.py` | `fabric-scep-hook`: Step-CA's SCEP webhooks (manual 1.5.3.3) — a minimal root service on a unix socket mounted into nginx (nginx's uid and root only), serving `POST /hooks/scep/challenge` (may this request be signed: a one-time challenge) and `POST /hooks/scep/issued` (record and link what was issued), answering only Step-CA's own client certificate (`fabriclib/pki/scep/answer_hook`) |
| `__init__.py` | Package marker (empty) |
