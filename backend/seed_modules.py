from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

client = MongoClient(os.getenv("MONGODB_URL"))
db = client[os.getenv("DATABASE_NAME", "vulnassess")]

# Clear existing modules
db.modules.delete_many({})

modules = [
    # Phase 1 (always on)
    {"module_key": "auth_test",        "name": "Authentication Testing",          "enabled": True,  "order": 1,  "fixed": True},
    # Phase 2
    {"module_key": "sql_injection",    "name": "SQL Injection",                   "enabled": True,  "order": 2,  "fixed": False},
    {"module_key": "xss",              "name": "Cross-Site Scripting (XSS)",      "enabled": True,  "order": 3,  "fixed": False},
    {"module_key": "command_injection","name": "OS Command Injection",            "enabled": True,  "order": 4,  "fixed": False},
    # Phase 3
    {"module_key": "ssrf",             "name": "Server-Side Request Forgery",     "enabled": True,  "order": 5,  "fixed": False},
    {"module_key": "xxe",              "name": "XML External Entity (XXE)",       "enabled": True,  "order": 6,  "fixed": False},
    # Phase 4
    {"module_key": "path_traversal",   "name": "Path Traversal / LFI / RFI",     "enabled": True,  "order": 7,  "fixed": False},
    {"module_key": "idor",             "name": "IDOR / Mass Assignment",          "enabled": True,  "order": 8,  "fixed": False},
    {"module_key": "open_redirect",    "name": "Open Redirect",                   "enabled": True,  "order": 9,  "fixed": False},
    {"module_key": "file_upload",      "name": "File Upload Vulnerabilities",     "enabled": True,  "order": 10, "fixed": False},
    # Security fundamentals
    {"module_key": "csrf",             "name": "CSRF Protection",                 "enabled": True,  "order": 11, "fixed": False},
    {"module_key": "security_headers", "name": "Security Headers",                "enabled": True,  "order": 12, "fixed": False},
    {"module_key": "ssl_tls",          "name": "SSL/TLS Analysis",                "enabled": True,  "order": 13, "fixed": False},
    {"module_key": "cors_check",       "name": "CORS Misconfiguration",           "enabled": True,  "order": 14, "fixed": False},
    {"module_key": "cookie_security",  "name": "Cookie Security",                 "enabled": True,  "order": 15, "fixed": False},
    {"module_key": "clickjacking",     "name": "Clickjacking Protection",         "enabled": True,  "order": 16, "fixed": False},
    {"module_key": "info_disclosure",  "name": "Information Disclosure",          "enabled": True,  "order": 17, "fixed": False},
    {"module_key": "rate_limiting",    "name": "Rate Limiting Check",             "enabled": True,  "order": 18, "fixed": False},
    # Phase 5
    {"module_key": "graphql",          "name": "GraphQL Introspection / BOLA",    "enabled": True,  "order": 19, "fixed": False},
    {"module_key": "api_key_leakage",  "name": "API Key Leakage",                 "enabled": True,  "order": 20, "fixed": False},
    {"module_key": "jwt",              "name": "JWT Security Attacks",            "enabled": True,  "order": 21, "fixed": False},
    {"module_key": "rate_limit",       "name": "Rate Limit Bypass",              "enabled": True,  "order": 22, "fixed": False},
]

for mod in modules:
    db.modules.insert_one(mod)

print(f"Seeded {db.modules.count_documents({})} modules.")