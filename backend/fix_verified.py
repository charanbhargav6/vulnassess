import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def fix():
    client = AsyncIOMotorClient('mongodb://localhost:27017')
    db = client['vulnassess']
    result = await db.users.update_many({}, {'$set': {'is_verified': True}})
    print(f'Updated {result.modified_count} users as verified')
    client.close()

asyncio.run(fix())