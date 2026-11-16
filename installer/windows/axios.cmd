@echo off
setlocal DisableDelayedExpansion

rem AXIOS starts a dedicated PowerShell process with an execution-policy
rem override scoped only to that process. No Windows policy is changed.
powershell.exe -NoLogo -NoExit -ExecutionPolicy Bypass -File "%~dp0axios.ps1" %*
exit /b %ERRORLEVEL%
