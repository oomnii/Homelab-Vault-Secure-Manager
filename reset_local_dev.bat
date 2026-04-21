@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" "%~dp0scripts\reset_local_dev.py" %*
) else (
  python "%~dp0scripts\reset_local_dev.py" %*
)
exit /b %ERRORLEVEL%
