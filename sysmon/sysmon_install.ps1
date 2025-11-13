<# Sysmon64 (x64) GPO kurulum script'i – TTTRADC-S002 paylaşıma göre
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

# Kaldırma modu
if ($Uninstall) {
  if (Is-Installed) {
    & "$ExeLocal" -u
    Start-Sleep 2
    sc.exe delete sysmon64 | Out-Null
  }
  exit 0
}

# Klasör hazırla ve dosyaları kopyala
if (!(Test-Path $LocalBin)) { New-Item -ItemType Directory -Path $LocalBin | Out-Null }
Copy-Item $ExeSrc $ExeLocal -Force
Copy-Item $CfgSrc $CfgLocal -Force

# İlk kurulum mu?
if (-not (Is-Installed)) {
  & "$ExeLocal" -accepteula -i "$CfgLocal"
  exit 0
}

# Çalışan konfig hash'i ile yeni konfig hash'ini karşılaştır
$running = & "$ExeLocal" -c 2>&1
$rx = $running | Select-String 'Configuration file hash:\s*([0-9A-F]+)' | Select-Object -First 1
$cfgHashRunning = if($rx){ $rx.Matches[0].Groups[1].Value } else { "" }
$cfgHashNew     = Get-Hash $CfgLocal

if ($ForceUpdate -or ($cfgHashRunning -ne $cfgHashNew)) {
  & "$ExeLocal" -c "$CfgLocal"
}
