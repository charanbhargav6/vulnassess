# VulnAssess Run Commands

Below are the exact commands you need to run each part of the VulnAssess project. 
It is recommended to open **4 separate terminal windows** so you can run the backend, web, and mobile apps simultaneously, leaving one terminal free for scripts.

---

## 1. Run the Backend (FastAPI)
The backend must be running for the Web and Mobile apps to work.

```powershell
cd C:\vulnassess\backend
# Use the project venv interpreter explicitly (avoids global Python conflicts):
..\.venv\Scripts\python.exe -m uvicorn main:app --reload
```
*Runs on: http://localhost:8000*

### Backend MongoDB Timeout Troubleshooting
If backend startup fails with `ServerSelectionTimeoutError`, use this quick checklist:

```powershell
# 1) Confirm your public IP
Invoke-RestMethod https://api.ipify.org

# 2) Check Atlas host reachability on Mongo port
Test-NetConnection ac-mkl9b1w-shard-00-00.kukw6dx.mongodb.net -Port 27017
Test-NetConnection ac-mkl9b1w-shard-00-01.kukw6dx.mongodb.net -Port 27017
Test-NetConnection ac-mkl9b1w-shard-00-02.kukw6dx.mongodb.net -Port 27017
```

Then verify in MongoDB Atlas:
1. Cluster is running (not paused).
2. `Network Access` includes your current public IP (or temporary `0.0.0.0/0` for development only).
3. Database user credentials in `backend/.env` are correct.

If all three tests above still fail on your Wi-Fi, switch to another network (mobile hotspot/VPN) and retry startup.

---

## 2. Run the Web App (React)
Open a **new terminal**:

```powershell
cd C:\vulnassess\web
npm install
npm start
```
*Runs on: http://localhost:3000*

---

## 3. Run the Mobile App (Expo / React Native)
Open a **new terminal**:

```powershell
cd C:\vulnassess\mobile
npm install
npx expo start --clear
```
*Note: Press `w` in the terminal to view in a web browser, or scan the QR code with the Expo Go app on your phone.*

---

## 4. Create and Manage Admin Accounts
If you need to add another administrator to the system, open a **new terminal** and run the interactive script:

```powershell
cd C:\vulnassess\backend
..\.venv\Scripts\python.exe scripts\create_admin.py
```
*The script will securely prompt you to type the new admin's email and password.*