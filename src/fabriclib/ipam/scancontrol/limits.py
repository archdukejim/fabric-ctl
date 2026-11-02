"""The limits of scans (decisions 2.1.10.26 and 2.1.10.38, manual 1.10.4.22, 1.10.4.36)."""

LARGEST = 1022            # a /22's hosts: a larger network is not scanned at once (2.1.10.26)
KEEP = 24 * 3600          # seconds a request is kept in AD (any state), then the serving site's poll removes it
RUN_WITHIN = 3600         # seconds a pending request may wait to be run; older, it is answered "expired"
MAX_PENDING = 4           # pending requests at one serving site (and one per subnet)
RESULT_LIMIT = 48000      # characters of a result written back into AD
PER_RUN = 1               # requests run by one run of the plan poll (a /22 takes about 12 s)
WAIT = 120                # seconds `fabricctl ipam scan --site` waits for the answer
