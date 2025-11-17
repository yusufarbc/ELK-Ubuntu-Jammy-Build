@echo off
setlocal

rem --- Marker dosyasi (sadece ilk sefer calismak icin) ---
set "MARKER=C:\ProgramData\metricbeat_installed.flag"

rem Eger marker varsa, daha once kurulmus demektir, hicbir sey yapma
if exist "%MARKER%" (
  echo [INFO] Metricbeat daha once kurulmus, scriptten cikiliyor...
  exit /b 0
)

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

  sc config "%SERVICE%" start= auto >nul

  sc start %SERVICE% >nul
)

rem --- Kurulum / guncelleme basarili olduysa marker olustur ---
rem Boylece bir sonraki reboot'ta script hicbir sey yapmadan hemen cikacak
type nul > "%MARKER%"

echo [OK] Metricbeat hazir.
exit /b 0
