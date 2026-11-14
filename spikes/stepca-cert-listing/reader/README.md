# reader

The prototype's Go reader for Step-CA's `badgerv2` database. `main.go` lists `x509_certs` and `x509_certs_data` with the
library Step-CA itself uses (`smallstep/nosql`, pinned in `go.mod`). `../run.py` builds it in `golang:1.24.4` and runs it against the live
directory, a copy, a stopped one and one after a restart. Throwaway (global Rule 4); the outcome is in
[2.3.5.5](../../../docs/volume_2_engineering_decisions/2.3.5-certificate-notes.md#2355-prototype-listing-the-certificates-step-ca-issues-itself).
