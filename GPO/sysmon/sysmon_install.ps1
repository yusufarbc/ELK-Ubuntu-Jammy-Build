# --- Sysmon64 sade GPO script (x64) ---
# UNC paylaşımından dosyaları kopyalar.
# Kurulu değilse kurar (-accepteula -i), kuruluysa konfigi uygular (-c).
# Amaç: minimum karmaşıklık, minimum hata.

$ErrorActionPreference = 'SilentlyContinue'

# Yollar
$Share = "\\TTTRADC-S002\elk\sysmon"
$Local = "C:\Program Files\Sysmon"

$ExeSrc = Join-Path $Share "Sysmon64.exe"
$CfgSrc = Join-Path $Share "sysmon.xml"

$ExeLocal = Join-Path $Local "Sysmon64.exe"
$CfgLocal = Join-Path $Local "sysmon.xml"

# Klasör oluştur
if (!(Test-Path $Local)) { New-Item -ItemType Directory -Path $Local | Out-Null }

# Dosyaları kopyala (üzerine yaz)
Copy-Item $ExeSrc $ExeLocal -Force -ErrorAction SilentlyContinue
Copy-Item $CfgSrc $CfgLocal -Force -ErrorAction SilentlyContinue

# Kurulu mu? (servis var mı bak)
$svc = Get-Service -Name sysmon64 -ErrorAction SilentlyContinue

if ($null -eq $svc) {
  # İlk kurulum
  & "$ExeLocal" -accepteula -i "$CfgLocal" *> $null
} else {
  # Mevcutsa her seferinde konfigi uygula (idempotent, sessiz)
  & "$ExeLocal" -c "$CfgLocal" *> $null
}

exit 0
