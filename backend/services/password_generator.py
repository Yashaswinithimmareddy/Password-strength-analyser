"""
Secure Password and Passphrase Generator Service
------------------------------------------------
Generates cryptographically random passwords and multi-word passphrases using Python's
`secrets` module (backed by the OS entropy source: /dev/urandom or Windows CryptGenRandom/BCryptGenRandom).

SECURITY NOTE:
Python's standard `random` module uses the Mersenne Twister algorithm (MT19937),
which is NOT cryptographically secure: an observer who captures 624 consecutive outputs
can reconstruct its internal state and predict all future outputs.
The `secrets` module MUST be used for generating cryptographic secrets, keys, and passwords.
Generated credentials are NEVER logged or saved.
"""
import secrets
import string

# Curated, clean, memorable dictionary for Diceware-style passphrases
DICEWARE_WORDS = [
    "amber", "beacon", "breeze", "canyon", "castle", "cedar", "cipher",
    "cloud", "comet", "coral", "crater", "crystal", "current", "dawn",
    "desert", "dolphin", "dragon", "drift", "echo", "ember", "falcon",
    "feather", "fern", "flame", "forest", "fossil", "galaxy", "glacier",
    "granite", "harbor", "haven", "horizon", "island", "jasper", "jungle",
    "lagoon", "lantern", "legend", "lunar", "marble", "meadow", "meteor",
    "mist", "mountain", "nebula", "oasis", "orbit", "peak", "pebble",
    "phoenix", "planet", "prism", "quartz", "radar", "rainbow", "ravine",
    "reef", "ripple", "river", "shadow", "shield", "silver", "solar",
    "spark", "sphere", "summit", "tempest", "timber", "torch", "valley",
    "vortex", "whisper", "willow", "zenith", "zephyr"
]

AMBIGUOUS_CHARS = set("il1Lo0O")

def generate_secure_password(
    length: int = 20,
    include_uppercase: bool = True,
    include_lowercase: bool = True,
    include_digits: bool = True,
    include_symbols: bool = True,
    avoid_ambiguous: bool = True
) -> dict:
    """
    Generate a cryptographically secure random password using Python's secrets module.

    Returns:
        dict: The transiently generated password and generation metadata.
    """
    length = max(8, min(64, length))
    char_pool = ""

    if include_lowercase:
        pool = string.ascii_lowercase
        if avoid_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)
        char_pool += pool

    if include_uppercase:
        pool = string.ascii_uppercase
        if avoid_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)
        char_pool += pool

    if include_digits:
        pool = string.digits
        if avoid_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)
        char_pool += pool

    if include_symbols:
        # Safe printable symbols
        safe_symbols = "!@#$%^&*()-_=+[]{}<>?"
        char_pool += safe_symbols

    if not char_pool:
        char_pool = string.ascii_letters + string.digits

    # Ensure at least one character from each requested category
    guaranteed = []
    if include_lowercase:
        lowers = [c for c in string.ascii_lowercase if not avoid_ambiguous or c not in AMBIGUOUS_CHARS]
        guaranteed.append(secrets.choice(lowers))
    if include_uppercase:
        uppers = [c for c in string.ascii_uppercase if not avoid_ambiguous or c not in AMBIGUOUS_CHARS]
        guaranteed.append(secrets.choice(uppers))
    if include_digits:
        digits = [c for c in string.digits if not avoid_ambiguous or c not in AMBIGUOUS_CHARS]
        guaranteed.append(secrets.choice(digits))
    if include_symbols:
        guaranteed.append(secrets.choice("!@#$%^&*()-_=+[]{}<>?"))

    # Fill remainder using CSPRNG secrets.choice
    remaining_length = length - len(guaranteed)
    remainder = [secrets.choice(char_pool) for _ in range(remaining_length)]

    # Combine and cryptographically shuffle
    password_chars = guaranteed + remainder
    # Fisher-Yates shuffle using secrets.randbelow
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    generated = "".join(password_chars)

    return {
        "password": generated,
        "length": len(generated),
        "entropy_source": "os_urandom_via_secrets_csprng",
        "type": "random_complex_password",
        "privacy_notice": "Generated transiently in memory; never saved to disk or logs."
    }

def generate_passphrase(word_count: int = 5, delimiter: str = "-") -> dict:
    """
    Generate a high-entropy Diceware-style multi-word passphrase.

    Returns:
        dict: The passphrase and metadata.
    """
    word_count = max(3, min(8, word_count))
    chosen_words = [secrets.choice(DICEWARE_WORDS) for _ in range(word_count)]
    passphrase = delimiter.join(chosen_words)

    # Calculate theoretical entropy for chosen words: log2(len(DICEWARE_WORDS)^word_count)
    import math
    word_pool_bits = round(word_count * math.log2(len(DICEWARE_WORDS)), 2)

    return {
        "passphrase": passphrase,
        "word_count": word_count,
        "delimiter": delimiter,
        "estimated_word_entropy_bits": word_pool_bits,
        "type": "multi_word_passphrase",
        "privacy_notice": "Generated transiently in memory; never saved to disk or logs."
    }
