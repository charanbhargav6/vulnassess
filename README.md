# VulnAssess Monorepo

This workspace contains the full VulnAssess stack:
- Backend API and scan engine (FastAPI)
- Web frontend (React)
- Mobile app (Expo / React Native)

## Folder Structure

```text
vulnassess/
  backend/   FastAPI API, scan engine, admin scripts
  web/       React web app
  mobile/    Expo React Native app
  .venv/     Shared local Python virtual environment
  RUN_COMMANDS.md
```

## Quick Start

### 1) Backend

```powershell
cd C:\vulnassess\backend
..\.venv\Scripts\python.exe -m uvicorn main:app --reload
```

### 2) Web

```powershell
cd C:\vulnassess\web
npm install
npm start
```

### 3) Mobile

```powershell
cd C:\vulnassess\mobile
npm install
npx expo start --clear
```

## Backend Utility Scripts

All operational scripts are under:

```text
backend/scripts/
```

Examples:
- `create_admin.py`
- `reset_admin.py`
- `benchmark.py`

Run scripts from `backend/` with the shared virtual environment:

```powershell
..\.venv\Scripts\python.exe scripts\create_admin.py
```

## Notes

- Keep sensitive values only in `.env` files.
- Do not use the scanner on systems without explicit permission.
