# tests/security

| File | What |
|---|---|
| `run.py` | The sign-in layers on a scratch install's settings: raises, lowerings only when asked for and recorded until raised back, Kerberos both ways, the audit entries, the relaxations status shows, setup refusing a lowering, `fabricctl security` refusing a lowering without its typed confirmation |
| `ufw_own_rule_args_test.py` | The host's own ufw rules split for ufw as a shell does: a comment's quotes go (the 0.10.0 rehearsal's `comment 'own-app'`, 2.3.1.57), lines that are not ufw commands and unclosed quotes give nothing; pure, in `settings` |
