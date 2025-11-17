@echo off
setlocal

rem --- Marker dosyasi (sadece ilk sefer calismak icin) ---
set "MARKER=C:\ProgramData\sysmon_installed.flag"

rem Eger marker varsa, daha once kurulmus demektir, hicbir sey yapma
if exist "%MARKER%" (
  echo [INFO] Sysmon daha once kurulmus, scriptten cikiliyor...
  exit /b 0
)

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

rem --- Kurulum / guncelleme basarili olduysa marker olustur ---
rem Boylece bir sonraki reboot'ta script hicbir sey yapmadan hemen cikacak
type nul > "%MARKER%"

echo [OK] Bitti.
exit /b 0