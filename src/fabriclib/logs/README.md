# fabriclib/logs

Optional log forwarding (design 2.1.15.1): Fluent Bit sends the host journal
(every fabric container logs there, fabric's audit log too) and OpenBao's
audit log to syslog (RFC 5424 over verified TLS) and/or Elasticsearch /
OpenSearch (HTTPS, verified), with a disk buffer.

| File | What |
|---|---|
| `deploy_fluentbit.py` | Fluent Bit's config, the CA that verifies each destination, its credentials file (root 0600, from fabric's secrets) and buffer folder |
| `fluentbit_pending.py` | Whether Fluent Bit waits for fabric's root CA: a fresh install's deploy runs before its PKI step, so setup's start step deploys it then |
| `log_status.py` | Per destination: records sent, retries, errors, dropped (Fluent Bit's metrics on fabric_net) |
| `run_logs_command.py` | `fabricctl logs status / set-password elastic` (password from a hidden prompt or stdin, never argv) |
