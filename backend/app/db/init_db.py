from app.db.database import get_database

DEFAULT_MODULES = [
    {"name": "Authentication", "module_key": "auth_module", "enabled": True, "order": 1, "fixed": True},
    {"name": "Reconnaissance", "module_key": "recon", "enabled": True, "order": 2, "fixed": False},
    {"name": "SQL Injection", "module_key": "sqli", "enabled": True, "order": 3, "fixed": False},
    {"name": "NoSQL Injection", "module_key": "nosqli", "enabled": True, "order": 4, "fixed": False},
    {"name": "XSS", "module_key": "xss", "enabled": True, "order": 5, "fixed": False},
    {"name": "CSRF", "module_key": "csrf", "enabled": True, "order": 6, "fixed": False},
    {"name": "Path Traversal", "module_key": "path_traversal", "enabled": True, "order": 7, "fixed": False},
    {"name": "OS Command Injection", "module_key": "cmd_injection", "enabled": True, "order": 8, "fixed": False},
    {"name": "Broken Access Control", "module_key": "broken_access", "enabled": True, "order": 9, "fixed": False},
    {"name": "IDOR", "module_key": "idor", "enabled": True, "order": 10, "fixed": False},
    {"name": "Mass Assignment", "module_key": "mass_assignment", "enabled": True, "order": 11, "fixed": False},
    {"name": "Security Headers", "module_key": "sec_headers", "enabled": True, "order": 12, "fixed": False},
    {"name": "Rate Limiting Check", "module_key": "rate_limit_check", "enabled": True, "order": 13, "fixed": False},
    {"name": "SSL/TLS Check", "module_key": "ssl_tls", "enabled": True, "order": 14, "fixed": False},
    {"name": "Port Scanner", "module_key": "port_scan", "enabled": True, "order": 15, "fixed": False},
]

async def init_db():
    db = get_database()

    # Keep critical query indexes in place for stable performance as data grows.
    await db.users.create_index([("email", 1)])
    await db.users.create_index([("created_at", -1)])

    await db.scans.create_index([("user_id", 1)])
    await db.scans.create_index([("created_at", -1)])
    await db.scans.create_index([("status", 1), ("created_at", -1)])
    await db.scans.create_index([("target_url", 1)])

    await db.schedules.create_index([("user_id", 1)])
    await db.schedules.create_index([("is_active", 1), ("next_run", 1)])

    await db.subscription_payments.create_index([("user_id", 1), ("created_at", -1)])
    await db.activity_logs.create_index([("timestamp", -1)])

    existing = await db.modules.count_documents({})
    if existing == 0:
        await db.modules.insert_many(DEFAULT_MODULES)
        print("Default modules inserted")
    else:
        # Update existing modules to add new ones
        for module in DEFAULT_MODULES:
            await db.modules.update_one(
                {"module_key": module["module_key"]},
                {"$setOnInsert": module},
                upsert=True
            )
        print("Modules updated")
    print("Database initialized")
