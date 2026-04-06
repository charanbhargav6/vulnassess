from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime
import os

load_dotenv()

client = MongoClient(os.getenv("MONGODB_URL"))
db = client[os.getenv("DATABASE_NAME", "vulnassess")]

db.users.update_one(
    {"email": "admin@vulnassess.com"},
    {"$set": {"created_at": datetime(2024, 1, 1)}}
)
print("Done!")