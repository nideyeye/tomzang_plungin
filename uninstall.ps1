# ============================================================
#  wb-firewall-guard 卸载（Windows / PowerShell）
#
#  默认只摘掉 $HOME\.workbuddy\settings.json 里的钩子，保留插件目录与 config.json。
#  加 -Purge 会连插件目录一起移除（先备份）。
#
#  用法:
#    powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
#    powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -Purge
# ============================================================

[CmdletBinding()]
param(
    [string]$Target = "",
    [string]$Settings = "",
    [switch]$Purge
)

$ErrorActionPreference = "Stop"

$PLUGIN_ID = "wb-firewall-guard"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Helper = Join-Path $Root "dist\install-helper.mjs"

function Write-Log([string]$Msg) {
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO]  $Msg"
}
function Write-ErrMsg([string]$Msg) {
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] $Msg" -ForegroundColor Red
}

$NodeBin = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $NodeBin) {
    $candidate = Join-Path $env:ProgramFiles "nodejs\node.exe"
    if (Test-Path $candidate) { $NodeBin = $candidate }
}
if (-not $NodeBin) { Write-ErrMsg "未找到 node，无法卸载"; exit 2 }

if (-not $Target) { $Target = Join-Path $HOME ".workbuddy\plugins\$PLUGIN_ID" }
if (-not $Settings) { $Settings = Join-Path $HOME ".workbuddy\settings.json" }

Write-Log "卸载目录: $Target"

$argsList = @("uninstall", "--target", $Target, "--settings", $Settings)
if ($Purge) { $argsList += @("--purge", "true") }

& $NodeBin $Helper @argsList
if ($LASTEXITCODE -ne 0) { Write-ErrMsg "卸载失败"; exit 2 }

Write-Log "卸载完成。重启 WorkBuddy 会话后生效。"
Write-Log "重装: powershell -ExecutionPolicy Bypass -File `"$(Join-Path $Root 'install.ps1')`""
