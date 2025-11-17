@echo off
setlocal

set "SHARE=\\TTTRADC-S002\elk\heartbeat"
set "MSI=%SHARE%\heartbeat.msi"
set "CFG=%SHARE%\heartbeat.yml"

set "INSTALL_DIR=C:\Program Files\Heartbeat"
set "SERVICE=heartbeat"

if not exist "%MSI%" (
  echo [ERR] heartbeat.msi bulunamadi: %MSI%
  exit /b 1
)
if not exist "%CFG%" (
  echo [ERR] heartbeat.yml bulunamadi: %CFG%
  exit /b 2
)

sc query %SERVICE% >nul 2>&1
if %errorlevel%==0 (
  echo [INFO] Heartbeat kurulu. Konfig güncelleniyor...

  copy "%CFG%" "%INSTALL_DIR%\heartbeat.yml" /Y >nul

  sc stop %SERVICE% >nul
  sc start %SERVICE% >nul
) else (
  echo [INFO] Ilk kurulum yapiliyor...

  msiexec /i "%MSI%" /quiet /norestart
  
  copy "%CFG%" "%INSTALL_DIR%\heartbeat.yml" /Y >nul
  
  "%INSTALL_DIR%\heartbeat.exe" install

  sc config "%SERVICE%" start= auto >nul

  sc start %SERVICE% >nul
)

echo [OK] Heartbeat hazir.
exit /b 0
