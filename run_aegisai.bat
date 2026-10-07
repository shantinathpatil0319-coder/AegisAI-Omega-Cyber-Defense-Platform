@echo off
title AegisAI Cyber Defense Platform
echo ========================================================
echo       🛡️ AegisAI Cyber Defense Platform Launcher
echo ========================================================
echo.
echo Launching AegisAI Server...
echo Opening Web Console in your default browser: http://127.0.0.1:5000
echo.
timeout /t 2 >nul
start http://127.0.0.1:5000
python backend/server.py
pause
