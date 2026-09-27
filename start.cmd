@echo off
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
  py -3 "%~dp0app.py" %*
) else (
  where python >nul 2>nul
  if errorlevel 1 (
    echo Install Python 3.11 or newer with Tcl/Tk and add Python to PATH.
    pause
    exit /b 1
  )
  python "%~dp0app.py" %*
)
