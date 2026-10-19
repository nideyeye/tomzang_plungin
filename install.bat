@echo off
setlocal
set SCRIPT_DIR=%~dp0

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%install.ps1" %*
set EXITCODE=%ERRORLEVEL%

if not "%EXITCODE%"=="0" (
  echo.
  echo [FAILED] install exit code: %EXITCODE%
) else (
  echo.
  echo [DONE] Restart the WorkBuddy session to take effect.
)
pause
endlocal & exit /b %EXITCODE%
