import hashlib


def hash_challenge(challenge):
    """Purpose: what the challenge store keeps instead of a challenge: its SHA-256 (the challenge is 192 random bits,
             so no salt or slow hash is needed to keep it from being guessed back).
    Inputs:  challenge — str.
    Returns: lower-case hex str.
    Fails:   never (non-str is formatted first).
    Feeds:   create_challenge, check_challenge."""
    return hashlib.sha256(str(challenge).encode()).hexdigest()
