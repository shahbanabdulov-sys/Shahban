@echo off
setlocal
cd /d "%~dp0"

REM Full web app server (accounts + progress).
REM Opens on port 5173: http://<PC-IP>:5173/

npm install
npm run start
