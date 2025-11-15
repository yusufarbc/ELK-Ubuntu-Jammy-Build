@echo off
setlocal

set "SHARE=\\TTTRADC-S002\elk\metricbeat"
set "MSI=%SHARE%\metricbeat.msi"
set "CFG=%SHARE%\metricbeat.yml"

set "INSTALL_DIR=C:\Program Files\Metricbeat"
set "SERVICE=metricbeat"

if not exist "%MSI%" (
  echo [ERR] metricbeat.msi bulunamadi: %MSI%
  exit /b 1
)
if not exist "%CFG%" (
  echo [ERR] metricbeat.yml bulunamadi: %CFG%
  exit /b 2
)

sc query %SERVICE% >nul 2>&1
if %errorlevel%==0 (
  echo [INFO] Metricbeat kurulu. Konfig güncelleniyor...

  copy "%CFG%" "%INSTALL_DIR%\metricbeat.yml" /Y >nul
  
  sc stop %SERVICE% >nul
  sc start %SERVICE% >nul
) else (
  echo [INFO] Ilk kurulum yapiliyor...

  msiexec /i "%MSI%" /quiet /norestart
  
  copy "%CFG%" "%INSTALL_DIR%\metricbeat.yml" /Y >nul
  
  "%INSTALL_DIR%\metricbeat.exe" install
  sc start %SERVICE% >nul
)

echo [OK] Metricbeat hazir.
exit /b 0