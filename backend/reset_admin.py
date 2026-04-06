"""VulnAssess emergency admin password reset utility.

Usage:
  1) Set MONGODB_URL in your environment.
  2) Optionally set DATABASE_NAME (defaults to "vulnassess").
  3) Run: python reset_admin.py
"""

import getpass
import os

from passlib.context import CryptContext
from pymongo import MongoClient


def main() -> None:
    mongodb_url = os.getenv("MONGODB_URL", "").strip()
    if not mongodb_url:
        print("Missing MONGODB_URL environment variable.")
        print("Example: set MONGODB_URL=mongodb+srv://<user>:<pass>@<cluster>/<db>")
        return

    database_name = os.getenv("DATABASE_NAME", "vulnassess").strip() or "vulnassess"
    email = (input("Admin email to reset [admin@vulnassess.com]: ").strip().lower() or "admin@vulnassess.com")
    new_password = getpass.getpass("New password: ")

    if len(new_password) < 10:
        print("Password must be at least 10 characters.")
        return

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    client = MongoClient(mongodb_url)
    db = client[database_name]

    user = db.users.find_one({"email": email})
    if not user:
        print(f"No user found with email: {email}")
        client.close()
        return

    db.users.update_one(
        {"email": email},
        {
            "$set": {
                "password_hash": pwd_context.hash(new_password),
                "is_active": True,
                "is_verified": True,
            }
        },
    )
    print("Password reset complete.")
    print(f"Email: {email}")
    print("Password: (hidden)")
    client.close()


if __name__ == "__main__":
    main()