from pathlib import Path

from fastapi import FastAPI, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI(title="VulnAssess Practice Target")
BASE_DIR = Path(__file__).resolve().parent


@app.get("/", response_class=HTMLResponse)
def home():
    return """<!doctype html>
<html>
  <head>
    <title>VulnAssess Practice Target</title>
    <meta charset='utf-8'>
    <style>
      body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.5; }
      .card { max-width: 720px; padding: 24px; border: 1px solid #ddd; border-radius: 12px; }
      a { color: #0a58ca; }
      input, button { padding: 8px 10px; margin: 4px 0; }
      code { background: #f3f3f3; padding: 2px 6px; border-radius: 4px; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>VulnAssess Practice Target</h1>
      <p>This is a local training app. It includes intentionally weak behaviors for scanner practice.</p>
      <ul>
        <li><a href="/login">Login form</a></li>
        <li><a href="/search?q=test">Reflected search page</a></li>
        <li><a href="/profile?name=guest">Profile page</a></li>
      </ul>
      <p>Try the scanner against <code>http://127.0.0.1:9000</code>.</p>
    </div>
  </body>
</html>"""


@app.get("/login", response_class=HTMLResponse)
def login_form():
    return """<!doctype html>
<html>
  <head><title>Login</title><meta charset='utf-8'></head>
  <body>
    <h1>Login</h1>
    <form method="post" action="/login">
      <label>Username</label><br>
      <input name="username" /><br>
      <label>Password</label><br>
      <input name="password" type="password" /><br><br>
      <button type="submit">Sign in</button>
    </form>
  </body>
</html>"""


@app.post("/login", response_class=HTMLResponse)
def login(username: str = Form(...), password: str = Form(...)):
    if username == "admin" and password == "password123":
        return RedirectResponse(url="/dashboard", status_code=302)
    return HTMLResponse(
        f"<h1>Login failed</h1><p>Invalid password for user <b>{username}</b>.</p>",
        status_code=401,
    )


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return "<h1>Dashboard</h1><p>Welcome back, admin.</p>"


@app.get("/search", response_class=HTMLResponse)
def search(q: str = Query("")):
    return f"""<!doctype html>
<html>
  <head><title>Search results</title><meta charset='utf-8'></head>
  <body>
    <h1>Search results</h1>
    <p>You searched for: {q}</p>
  </body>
</html>"""


@app.get("/profile", response_class=HTMLResponse)
def profile(name: str = Query("guest")):
    return f"<h1>Profile</h1><p>User: {name}</p><p>Status: active</p>"


@app.get("/files", response_class=HTMLResponse)
def files(name: str = Query("readme.txt")):
    target = (BASE_DIR / "files" / name).resolve()
    try:
        content = target.read_text(encoding="utf-8")
    except Exception:
        content = f"Could not read file: {name}"
    return f"<h1>File viewer</h1><pre>{content}</pre>"
