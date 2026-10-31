# scripts/release

Release chores the repository's owner runs by hand (manual 3.14.1).

| File | What |
|---|---|
| `make-apt-key.sh` | Make the apt repository's signing key once and store it in the Actions secrets, with an offline copy (the key, its passphrase, the revocation certificate) in a folder you keep offline |
| `rename-apt-key.sh` | Give that key fabric-ctl's name, the same key (2.1.3.5, manual 3.14.1.6): a new primary user ID from the offline copy, stored back in `GPG_PRIVATE_KEY`; the fingerprint never changes |
