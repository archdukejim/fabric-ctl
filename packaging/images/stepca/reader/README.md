# jinja/stepca/build/reader

`fabric-certlist <db dir>`: every certificate in Step-CA's own database, one JSON
line each (serial, subject, names, dates, CA flag, provisioner and its type), so
the PKI page can list and revoke the certificates LAN machines got over ACME and
anything else Step-CA signed (decision 2.1.5.13, manual 1.5.1.9.1). Built in the
first stage of `../Dockerfile`, cross-compiled with `CGO_ENABLED=0`, and copied
into the Step-CA image. fabric runs it in a throwaway container of that image,
with no network, a read-only root, no capabilities and 256 MB, against a copy of
the database (`fabriclib/pki/list_stepca_certs.py`): never inside Step-CA itself.

| File | What |
|---|---|
| `main.go` | Opens the copy with smallstep/nosql's BadgerDB v2 driver, read-only, and prints `x509_certs` with the provisioner from `x509_certs_data`; exit 2 usage, 3 the database cannot be opened, 4 a row cannot be read |
| `go.mod`, `go.sum` | The modules, pinned to the versions step-ca 0.30.2 builds with (`github.com/smallstep/nosql v0.8.0`, BadgerDB v2.2007.4), so it reads the database format the pinned Step-CA writes |

Only the `nosql/badger/v2` driver is imported, never nosql's root package, which
would link the MySQL driver (MPL-2.0). Every module linked is MIT, Apache-2.0 or
BSD; their notices are in `THIRD_PARTY_NOTICES` (manual 1.1.7.3). When the
pinned `image_stepca` moves to a step-ca built with other nosql or Badger
versions, these follow it (`go get`, then `go mod tidy`), in the same change.
