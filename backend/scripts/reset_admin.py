"""VulnAssess admin password reset utility."""

import getpass
import os
import sys

from passlib.context import CryptContext
from pymongo import MongoClient

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def main():
    email = (input("Admin email to reset [admin@vulnassess.com]: ").strip().lower() or "admin@vulnassess.com")
    new_password = getpass.getpass("New password: ")

    if len(new_password) < 10:
        print("Password must be at least 10 characters.")
        return

    client = MongoClient(settings.MONGODB_URL)
    db = client[settings.DATABASE_NAME]

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