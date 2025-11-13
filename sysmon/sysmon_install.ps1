<# Sysmon64 (x64) GPO kurulum script'i – UNC paylaşıma göre
 - İlk kurulum: -accepteula ile
 - Güncelleme: sysmon.xml hash değişirse -c ile
 - Kaldırma: -Uninstall parametresi
#>

param(
  [switch]$Uninstall,
  [switch]$ForceUpdate
)

$ErrorActionPreference = 'Stop'

$ShareRoot = "\\TTTRADC-S002\elk\sysmon"
$LocalBin  = "C:\Program Files\Sysmon"

$ExeSrc    = Join-Path $ShareRoot "Sysmon64.exe"
$CfgSrc    = Join-Path $ShareRoot "sysmon.xml"

$ExeLocal  = Join-Path $LocalBin "Sysmon64.exe"
$CfgLocal  = Join-Path $LocalBin "sysmon.xml"

function Is-Installed { try { sc.exe query sysmon64 | Out-Null; $true } catch { $false } }
function Get-Hash($p){ if(Test-Path $p){ (Get-FileHash $p -Algorithm SHA256).Hash.ToUpper() } else { "" } }

# Kaldırma
if ($Uninstall) {
  if (Is-Installed) {
    & "$ExeLocal" -u
    Start-Sleep 2
    sc.exe delete sysmon64 | Out-Null
  }
  exit 0
}

# Klasör oluştur + dosyaları kopyala
if (!(Test-Path $LocalBin)) { New-Item -ItemType Directory -Path $LocalBin | Out-Null }
Copy-Item $ExeSrc $ExeLocal -Force
Copy-Item $CfgSrc $CfgLocal -Force

# 1) İlk kurulum değilse kur
if (-not (Is-Installed)) {
  & "$ExeLocal" -accepteula -i "$CfgLocal"
  exit 0
}

# 2) Kuruluysa: çalışan config hash'ini güvenle oku (hata üretmeden)
$cfgHashRunning = ""
try {
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $out = (& "$ExeLocal" -c 2>&1) | Out-String
  $ErrorActionPreference = $prev
  $m = [regex]::Match($out,'Configuration file hash:\s*([0-9A-F]+)')
  if ($m.Success) { $cfgHashRunning = $m.Groups[1].Value }
} catch { $cfgHashRunning = "" }

$cfgHashNew = Get-Hash $CfgLocal

# 3) Değişmişse veya zorla: yeni konfigi uygula
if ($ForceUpdate -or ($cfgHashRunning -ne $cfgHashNew)) {
  & "$ExeLocal" -c "$CfgLocal" *> $null
}
