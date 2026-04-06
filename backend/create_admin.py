import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from datetime import datetime

pwd = CryptContext(schemes=['bcrypt'])

async def create():
    client = AsyncIOMotorClient('mongodb://localhost:27017')
    db = client['vulnassess']
    existing = await db.users.find_one({'email': 'admin@vulnassess.com'})
    if existing:
        print('Admin already exists!')
        client.close()
        return
    await db.users.insert_one({
        'email': 'admin@vulnassess.com',
        'password_hash': pwd.hash('Admin@123'),
        'role': 'admin',
        'created_at': datetime.utcnow()
    })
    print('Admin created successfully!')
    print('Email:    admin@vulnassess.com')
    print('Password: Admin@123')
    client.close()

asyncio.run(create())
