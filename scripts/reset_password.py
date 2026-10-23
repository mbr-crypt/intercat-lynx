"""
Emergency reset of a user's password (for example the only administrator).

Run inside the backend container:

    docker compose exec backend python scripts/reset_password.py <username>

It asks for the new password (not shown while typing), applies the normal
password rules, ends all existing logins of that user, unlocks the account and
forces a password change at the next login. Two-factor login stays active; if
the authenticator is lost as well, add --disable-2fa.

Needs shell access to the server, which is the point: nobody on the internet
can use it.
"""

import argparse
import getpass
import sys

sys.path.insert(0, ".")

from backend.database import SessionLocal  # noqa: E402
from backend.models import User  # noqa: E402
from backend.security import passwords  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("username")
    parser.add_argument("--disable-2fa", action="store_true", help="also switch off two-factor login")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        user = (
            db.query(User)
            .filter((User.username == args.username) | (User.email == args.username))
            .first()
        )
        if user is None:
            print(f"No user '{args.username}' found.", file=sys.stderr)
            return 1

        first = getpass.getpass("New password: ")
        if first != getpass.getpass("Repeat: "):
            print("The passwords differ.", file=sys.stderr)
            return 1
        if len(first) < 12:
            print("Password rejected: at least 12 characters (as in the setup assistant).", file=sys.stderr)
            return 1
        try:
            passwords.validate_strength(first)
        except ValueError as exc:
            print(f"Password rejected: {exc}", file=sys.stderr)
            return 1

        user.hashed_password = passwords.hash_password(first)
        user.must_change_password = True
        user.token_version += 1
        user.failed_login_attempts = 0
        user.locked_until = None
        user.is_active = True
        if args.disable_2fa:
            user.totp_enabled = False
            user.totp_secret_enc = None
        db.commit()
        print(f"Password of '{user.username}' changed. All sessions ended.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
