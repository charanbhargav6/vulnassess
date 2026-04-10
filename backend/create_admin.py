import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from datetime import datetime
import getpass

pwd = CryptContext(schemes=['bcrypt'])

async def create():
    client = AsyncIOMotorClient('mongodb://localhost:27017')
    db = client['vulnassess']
    existing = await db.users.find_one({'email': 'admin@vulnassess.com'})
    if existing:
        print('Admin already exists!')
        client.close()
        return

    password = getpass.getpass('Enter admin password: ')
    if not password:
        print('Password cannot be empty.')
        client.close()
        return
    if len(password) < 10:
        print('Password must be at least 10 characters.')
        client.close()
        return
    await db.users.insert_one({
        'email': 'admin@vulnassess.com',
        'password_hash': pwd.hash(password),
        'role': 'admin',
        'created_at': datetime.utcnow()
    })
    print('Admin created successfully!')
    print('Email:    admin@vulnassess.com')
    client.close()

asyncio.run(create())
