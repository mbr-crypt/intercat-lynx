"""
Check that SECRET_KEY is a real secret and not an example value.

Why this exists: ``.env.example`` used to contain ``your-secret-key-here-...``.
Copying the file and forgetting to change it made every login token forgeable,
because the key is public in the repository. In production the backend now
refuses to start with such a value.
"""

MIN_LENGTH = 32

# Values that appear in the repository, documentation or older examples
KNOWN_PLACEHOLDERS = (
    "change-me",
    "changeme",
    "your-secret",
    "your-csrf",
    "your_secret",
    "replace-me",
    "replace_me",
    "secret-key-here",
    "example",
)


def weakness(value: str) -> str:
    """Empty string if the key is acceptable, otherwise the reason it is not."""
    if not value:
        return "is empty"
    if len(value) < MIN_LENGTH:
        return f"is shorter than {MIN_LENGTH} characters"
    lowered = value.lower()
    for marker in KNOWN_PLACEHOLDERS:
        if marker in lowered:
            return "is an example value from the documentation"
    if len(set(value)) < 8:
        return "has too little variety"
    return ""
