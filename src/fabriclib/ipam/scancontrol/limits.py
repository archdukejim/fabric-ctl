"""The limits of scans from the top down (decision 2.1.10.30, manual 1.10.4.29.3)."""

KEEP = 24 * 3600          # seconds a request is kept in AD (any state), then the branch's poll removes it
RUN_WITHIN = 3600         # seconds a pending request may wait to be run; older, it is answered "expired"
MAX_PENDING = 4           # pending requests at one branch (and one per subnet)
RESULT_LIMIT = 48000      # characters of a result written back into AD
PER_RUN = 1               # requests run by one run of the plan poll (a /22 takes about 12 s)
WAIT = 120                # seconds `fabricctl ipam scan --site` waits for the answer
