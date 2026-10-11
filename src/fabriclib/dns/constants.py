RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "SRV"]
# a zone under these needs no "Hide the public name" (manual 1.4.1.3): the private-use names (RFC 6761, ICANN's
# .internal; home.arpa, RFC 8375, is checked apart) and the common home ones: no public answer is hidden
PRIVATE_TLDS = ("internal", "lan", "local", "test", "localhost", "invalid", "example")
