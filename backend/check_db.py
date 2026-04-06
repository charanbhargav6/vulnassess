import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def check():
    client = AsyncIOMotorClient('mongodb://localhost:27017')
    db = client['vulnassess']
    
    users = await db.users.count_documents({})
    scans = await db.scans.count_documents({})
    modules = await db.modules.count_documents({})
    
    print(f'Users: {users}')
    print(f'Scans: {scans}')
    print(f'Modules: {modules}')
    
    print('\nLast 3 scans:')
    async for scan in db.scans.find(sort=[('created_at', -1)], limit=3):
        print(f'  - {scan["target_url"]} | {scan["status"]} | score: {scan.get("total_risk_score", 0)}')
    
    client.close()

asyncio.run(check())
