@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" app.py %*
  goto finished
)
where py >nul 2>nul
if not errorlevel 1 (
  py -3 app.py %*
  goto finished
)
where python >nul 2>nul
if not errorlevel 1 (
  python app.py %*
  goto finished
)
echo Python 3.10 or newer is required. Install Python, then run this file again.
pause
exit /b 1
:finished
if errorlevel 1 pause
endlocal
