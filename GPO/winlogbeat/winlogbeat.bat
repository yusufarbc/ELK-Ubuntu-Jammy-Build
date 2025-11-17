@echo off
setlocal

rem --- Marker dosyasi (sadece ilk sefer calismak icin) ---
set "MARKER=C:\ProgramData\winlogbeat_installed.flag"

rem Eger marker varsa, daha once kurulmus demektir, hicbir sey yapma
if exist "%MARKER%" (
  echo [INFO] Winlogbeat daha once kurulmus, scriptten cikiliyor...
  exit /b 0
)

rem --- Paylaşım yolu ---
set "SHARE=\\TTTRADC-S002\elk\winlogbeat"
set "MSI=%SHARE%\winlogbeat.msi"
set "CFG=%SHARE%\winlogbeat.yml"

set "INSTALL_DIR=C:\Program Files\Winlogbeat"
set "SERVICE=winlogbeat"

rem --- Dosya kontrolleri ---
if not exist "%MSI%" (
  echo [ERR] winlogbeat.msi bulunamadi: %MSI%
  exit /b 1
)
if not exist "%CFG%" (
  echo [ERR] winlogbeat.yml bulunamadi: %CFG%
  exit /b 2
)

rem --- Servis var mı? ---
sc query %SERVICE% >nul 2>&1
if %errorlevel%==0 (
  echo [INFO] Winlogbeat kurulu. Konfig güncelleniyor...
  
  copy "%CFG%" "%INSTALL_DIR%\winlogbeat.yml" /Y >nul
  
  sc stop %SERVICE% >nul
  sc start %SERVICE% >nul
) else (
  echo [INFO] Ilk kurulum yapiliyor...

  msiexec /i "%MSI%" /quiet /norestart
  
  copy "%CFG%" "%INSTALL_DIR%\winlogbeat.yml" /Y >nul
  
  "%INSTALL_DIR%\winlogbeat.exe" install

  sc config "%SERVICE%" start= auto >nul
  
  sc start %SERVICE% >nul
)

rem --- Kurulum / guncelleme basarili olduysa marker olustur ---
rem Boylece bir sonraki reboot'ta script hicbir sey yapmadan hemen cikacak
type nul > "%MARKER%"

echo [OK] Winlogbeat hazir.
exit /b 0
