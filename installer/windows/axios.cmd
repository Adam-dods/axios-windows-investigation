@echo off
setlocal
rem Keep Results available across separate CMD invocations for this Windows user.
set "AXIOS_CMD_SESSION=1"
set "AXIOS_SESSION_DIRECTORY=%LOCALAPPDATA%\AXIOS\cmd-session"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0axios.ps1" %*
exit /b %ERRORLEVEL%
