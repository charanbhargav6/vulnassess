# VulnAssess

VulnAssess is a full-stack web vulnerability assessment platform built with FastAPI, React, React Native, and MongoDB. It provides authenticated scanning, real-time scan progress, PDF reporting, AI-assisted remediation, and an admin dashboard for managing users, scans, modules, and payments.

## What It Does

- Scans web applications for common security issues such as SQL injection, XSS, CSRF, SSRF, IDOR, insecure headers, weak JWT handling, and exposed API keys.
- Runs an async scan engine with multiple modules and progress tracking.
- Supports user authentication, scan history, scheduled scans, and comparison of scan results.
- Generates downloadable PDF reports and AI remediation guidance.
- Includes mobile and web frontends plus an admin panel for operations.

## Project Layout

- `backend/` FastAPI API, scan engine, MongoDB integration, scripts, and backend documentation.
- `web/` React web app for dashboard, scans, reports, and admin use.
- `mobile/` React Native app for Android/iOS with secure token storage.

## Architecture Overview

1. The web or mobile client authenticates with the backend.
2. The backend issues a session token and enforces CSRF and role checks.
3. Scan requests are stored in MongoDB and executed by the async scan engine.
4. The engine crawls the target, runs vulnerability modules, stores findings, and updates progress.
5. Reports and AI remediation data are returned through the API.

For a deeper explanation of how the system works, see [docs/OVERVIEW.md](docs/OVERVIEW.md).

## Key Features

- Async FastAPI backend with MongoDB persistence.
- Scan module pipeline with rate limiting and cancellation support.
- Admin overview endpoint for faster dashboard loading.
- Mobile and web admin interfaces.
- AI remediation reports powered by Anthropic.
- Public-safe `.env.example` template and secret-safe repository setup.

## Local Setup

### Backend

```bash
cd backend
# Windows PowerShell
Copy-Item .env.example .env

# macOS/Linux
# cp .env.example .env
pip install -r requirements.txt
uvicorn main:app --reload
```

### Web

```bash
cd web
npm install
npm start
```

### Mobile

```bash
cd mobile
npm install
npx expo start
```

## How To Update The Repo

After making changes locally:

```bash
git status
git add .
git commit -m "Describe your change clearly"
git push
```

If you want to publish a major milestone, keep the commit message focused on the outcome, for example:

```bash
git commit -m "Improve scan performance and admin loading"
```

## Public Repo Safety

Before making the repository public:

- Keep real secrets only in `.env` files.
- Commit only `.env.example` templates.
- Never commit API keys, database URLs, or production secrets.
- Keep dependency folders and build artifacts ignored.

## Resume-Friendly Description

VulnAssess is a full-stack vulnerability scanning platform built with FastAPI, React, React Native, and MongoDB. It includes an async scan engine, admin operations, PDF reporting, and AI remediation support for web application security assessment.
