# ============================================================
#  wb-firewall-guard 一键安装（Windows / PowerShell）
#
#  做了什么：
#    1. 部署插件到 $HOME\.workbuddy\plugins\wb-firewall-guard（旧版本自动备份，只留最近 3 份）
#    2. 写入 config.json（firewallUrl / authKey / debug / blockTip …）
#    3. 备份 $HOME\.workbuddy\settings.json 并把 6 个钩子合并进去（幂等）
#    4. 向防火墙后端注册本机设备（device_id 与插件运行时同源）
#    5. 校验钩子已生效
#
#  用法（PowerShell，管理员权限非必需）：
#    .\install.ps1 -FirewallUrl http://${防火墙服务地址}/ -AuthKey ${页面上生成的 key}
#    .\install.ps1 -DebugLog true -SkipRegister
#
#  双击 install.bat 等同于以默认参数运行本脚本。
# ============================================================

[CmdletBinding()]
param(
    [string]$FirewallUrl = "",
    [string]$AuthKey = "",
    [string]$DebugLog = "",
    [string]$BlockTip = "",
    [string]$Target = "",
    [string]$Settings = "",
    [switch]$SkipRegister,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

$PLUGIN_ID = "wb-firewall-guard"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Helper = Join-Path $Root "dist\install-helper.mjs"

function Write-Log([string]$Msg) {
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO]  $Msg"
}
function Write-WarnMsg([string]$Msg) {
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [WARN]  $Msg" -ForegroundColor Yellow
}
function Write-ErrMsg([string]$Msg) {
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] $Msg" -ForegroundColor Red
}

function Show-Usage {
    Write-Host @"

用法: .\install.ps1 [-FirewallUrl <url>] [-AuthKey <key>] [-DebugLog true|false]
                   [-BlockTip <文案>] [-Target <安装目录>] [-Settings <settings.json>]
                   [-SkipRegister]

  -FirewallUrl  防火墙后端地址（必填，包内 config.example.json 只是占位符模板）
  -AuthKey      防火墙认证密钥（必填，也可用环境变量 WB_FIREWALL_AUTH_KEY 传入）
  -DebugLog     是否开启调试日志 true/false
  -BlockTip     拦截时展示给用户的提示文案
  -SkipRegister 跳过设备注册（后端无 register 接口或离线安装时用）

示例:
  .\install.ps1 -FirewallUrl http://`${防火墙服务地址} -AuthKey `${页面上生成的 key}

"@
}

if ($Help) { Show-Usage; exit 0 }

# -------- 依赖：node --------
function Find-Node {
    $cmd = Get-Command node -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $candidates = @(
        (Join-Path $env:ProgramFiles "nodejs\node.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "nodejs\node.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\nodejs\node.exe"),
        (Join-Path $env:USERPROFILE ".nvm\current\node.exe"),
        (Join-Path $env:USERPROFILE "AppData\Local\fnm\node.exe"),
        (Join-Path $env:USERPROFILE ".volta\bin\node.exe")
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    return $null
}

$NodeBin = Find-Node
if (-not $NodeBin) {
    Write-ErrMsg "未找到 node（需要 >= 18）。请先安装 Node.js: https://nodejs.org/"
    exit 2
}
$nodeVersion = (& $NodeBin --version 2>$null)
Write-Log "node = $NodeBin ($nodeVersion)"

if (-not (Test-Path $Helper)) {
    Write-ErrMsg "找不到安装内核: $Helper（安装包不完整）"
    exit 2
}

# -------- 默认值：命令行参数 > 环境变量 > 包内 config.example.json --------
function Read-Default([string]$File, [string]$Key) {
    if (-not (Test-Path $File)) { return "" }
    try {
        $json = Get-Content $File -Raw -Encoding UTF8 | ConvertFrom-Json
        $val = $json.$Key
        if ($val) { return [string]$val }
    } catch { }
    return ""
}

$Example = Join-Path $Root "config.example.json"
# 环境变量优先于包内模板（模板里是 ${...} 占位符，不换掉会被下面的校验拦下）
if (-not $FirewallUrl -and $env:WB_FIREWALL_URL) { $FirewallUrl = $env:WB_FIREWALL_URL; Write-Log "firewallUrl 取自环境变量 WB_FIREWALL_URL" }
if (-not $AuthKey -and $env:WB_FIREWALL_AUTH_KEY) { $AuthKey = $env:WB_FIREWALL_AUTH_KEY; Write-Log "authKey 取自环境变量 WB_FIREWALL_AUTH_KEY" }
if (-not $FirewallUrl) { $FirewallUrl = Read-Default $Example "firewallUrl" }
if (-not $AuthKey) { $AuthKey = Read-Default $Example "authKey" }
if (-not $DebugLog) { $DebugLog = "false" }

# -------- 校验：空值或未替换的 ${...} 占位符一律拒绝，逼使用者在命令行填真实值 --------
if ((-not $FirewallUrl) -or ($FirewallUrl.Contains('${')) -or (-not $AuthKey) -or ($AuthKey.Contains('${'))) {
    Write-ErrMsg 'firewallUrl / authKey 未填写，或仍是 ${...} 占位符（包内 config.example.json 只是模板）。'
    Write-ErrMsg '请在命令行传入真实值，例如：'
    Write-ErrMsg '  .\install.ps1 -FirewallUrl http://<防火墙服务地址> -AuthKey <页面上生成的key>'
    exit 2
}

if (-not $Target) { $Target = Join-Path $HOME ".workbuddy\plugins\$PLUGIN_ID" }
if (-not $Settings) { $Settings = Join-Path $HOME ".workbuddy\settings.json" }

Write-Log "安装目录: $Target"
Write-Log "配置文件: $Settings"

# -------- Step 1: 部署 --------
Write-Log "Step 1/5  部署插件文件"
& $NodeBin $Helper deploy --source $Root --target $Target
if ($LASTEXITCODE -ne 0) { Write-ErrMsg "部署插件文件失败"; exit 2 }

# -------- Step 2: 写配置 --------
Write-Log "Step 2/5  写入 config.json"
$configArgs = @("config", "--target", $Target, "--url", $FirewallUrl, "--key", $AuthKey, "--debug", $DebugLog)
if ($BlockTip) { $configArgs += @("--tip", $BlockTip) }
& $NodeBin $Helper @configArgs
if ($LASTEXITCODE -ne 0) { Write-ErrMsg "写入 config.json 失败"; exit 2 }

# -------- Step 3: 挂钩子 --------
Write-Log "Step 3/5  挂载 WorkBuddy 钩子"
& $NodeBin $Helper hooks --target $Target --settings $Settings
if ($LASTEXITCODE -ne 0) { Write-ErrMsg "挂载钩子失败"; exit 2 }

# -------- Step 4: 设备注册 --------
if ($SkipRegister) {
    Write-Log "Step 4/5  跳过设备注册（-SkipRegister）"
} else {
    Write-Log "Step 4/5  向防火墙后端注册设备"
    & $NodeBin $Helper register --url $FirewallUrl --key $AuthKey
    if ($LASTEXITCODE -ne 0) {
        Write-ErrMsg "设备注册失败。插件已安装但后端可能拒绝该设备的审计请求。"
        Write-ErrMsg "可加 -SkipRegister 强制安装；或恢复备份后排查网络/密钥。"
        Write-ErrMsg "配置文件备份目录: $(Split-Path $Settings -Parent)"
        exit 3
    }
}

# -------- Step 5: 校验 --------
Write-Log "Step 5/5  校验安装结果"
& $NodeBin $Helper verify --target $Target --settings $Settings
if ($LASTEXITCODE -ne 0) { Write-ErrMsg "校验未通过"; exit 4 }

Write-Host ""
Write-Host "------------------------------------------------------------"
Write-Host "安装完成。"
Write-Host ""
Write-Host "  插件目录  $Target"
Write-Host "  配置文件  $Settings"
Write-Host "  日志      $(Join-Path $Target 'logs\guard.log')"
Write-Host ""
Write-Host "生效方式：完全退出并重启 WorkBuddy 会话（钩子只在会话启动时加载）。"
Write-Host ""
Write-Host "其它命令："
Write-Host "  卸载    powershell -ExecutionPolicy Bypass -File `"$(Join-Path $Root 'uninstall.ps1')`""
Write-Host "  自检    echo {`"prompt`":`"hello`"} | & `"$NodeBin`" `"$(Join-Path $Target 'dist\guard.mjs')`" input"
Write-Host "------------------------------------------------------------"
