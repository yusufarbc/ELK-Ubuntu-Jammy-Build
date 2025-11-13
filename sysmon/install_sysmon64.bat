@echo off
setlocal

rem --- Paylaşım yolu ---
set "SHARE=\\TTTRADC-S002\elk\sysmon"
set "EXE=%SHARE%\Sysmon64.exe"
set "CFG=%SHARE%\sysmon.xml"

if not exist "%EXE%" (
  echo [ERR] Sysmon64.exe bulunamadi: %EXE%
  exit /b 1
)
if not exist "%CFG%" (
  echo [ERR] sysmon.xml bulunamadi: %CFG%
  exit /b 2
)

rem Sysmon servisi var mi?
sc query sysmon64 >nul 2>&1
if %errorlevel%==0 (
  echo [INFO] Mevcut kurulum bulundu. Konfig uygulanacak...
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "& '%EXE%' -c '%CFG%'"  >nul 2>&1
) else (
  echo [INFO] Ilk kurulum yapiliyor...
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "& '%EXE%' -accepteula -i '%CFG%'"  >nul 2>&1
)

echo [OK] Bitti.
exit /b 0