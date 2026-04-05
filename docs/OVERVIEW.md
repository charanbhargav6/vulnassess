# VulnAssess Overview

## Purpose

VulnAssess is a web application security assessment platform designed to scan targets for common vulnerabilities, store and compare results, and help users review findings through dashboards and reports.

## How It Works

### 1. Authentication
- Users register and sign in through the backend.
- The backend issues a session token or bearer token depending on the client.
- Role-based checks protect admin endpoints and sensitive operations.

### 2. Scanning
- A scan request is created with a target URL and optional credentials.
- The backend stores the scan record in MongoDB and dispatches the scan engine.
- The scan engine crawls the target, collects forms, links, scripts, and response data.
- Vulnerability modules execute against the target and append findings to the scan.

### 3. Reporting
- Scan results are saved in MongoDB.
- Users can open scan details, download PDF reports, and review severity breakdowns.
- AI remediation endpoints can generate suggested fixes for completed scans.

### 4. Admin Workflow
- Admin users can manage users, modules, payments, logs, and scans.
- The admin overview endpoint returns a combined payload so the dashboard loads faster.
- Client-side caches reduce unnecessary refreshes while still invalidating after mutations.

## Performance Improvements Already Added

- MongoDB indexes for scans, users, schedules, payments, and logs.
- Request-scoped authenticated user caching.
- Aggregation-based admin user counting instead of N+1 queries.
- Exponential backoff polling on the dashboard.
- Consolidated admin overview endpoint for fewer round trips.
- Scan module parallelization with controlled concurrency.
- Field projection for list endpoints to reduce payload size.

## Repo Structure

- `backend/` API, database layer, scanner, scripts, and backend docs.
- `web/` React dashboard and admin UI.
- `mobile/` React Native app for on-device usage.

## GitHub Publishing Notes

To keep the repo professional and safe:

- Commit code, docs, and templates.
- Do not commit `.env` or any secret keys.
- Use the included `.env.example` files for local setup.
- Keep generated build output out of the repository unless you explicitly want deployment artifacts.
