#!/usr/bin/env pwsh
# OpenCode 插件跨平台安装脚本
# 支持 Windows、Linux、macOS

param(
    [string]$Mode = "project",
    [string]$ProjectDir = $PWD,
    [string]$FirewallUrl = "",
    [string]$AuthKey = "",
    [string]$BlockMessage = "当前请求包含敏感信息，已被安全组件拦截",
    [int]$FirewallTimeout = 3000,
    [switch]$Debug,
    [switch]$SkipValidation,
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments)]
    [string[]]$PositionalArgs
)

# 处理位置参数
if ($PositionalArgs.Count -gt 0) {
    $FirewallUrl = $PositionalArgs[0]
}
if ($PositionalArgs.Count -gt 1) {
    $AuthKey = $PositionalArgs[1]
}

# 显示帮助
if ($Help) {
    @"

OpenCode 插件跨平台安装脚本

用法: .\install.ps1 [选项] [firewall-url] [auth-key]

选项:
    -Mode <MODE>              安装模式: project (项目级) 或 global (全局级) [默认: project]
    -ProjectDir <PATH>        项目目录 [默认: 当前目录]
    -FirewallUrl <URL>        防火墙服务地址
    -AuthKey <KEY>            认证密钥
    -BlockMessage <MSG>       拦截提示消息
    -FirewallTimeout <MS>     超时时间(毫秒) [默认: 3000]
    -Debug                    启用调试模式
    -SkipValidation           跳过配置验证
    -Help                     显示此帮助信息

位置参数:
    firewall-url              防火墙服务地址
    auth-key                  认证密钥

示例:
    # 快速安装
    .\install.ps1 http://firewall-url auth-key

    # 全局安装
    .\install.ps1 -Mode global http://firewall-url auth-key

    # 一键安装命令
    irm https://raw.githubusercontent.com/nideyeye/tomzang_plungin/open-code/install.ps1 | iex -- http://firewall-url auth-key

"@ | Write-Host
    exit 0
}

# 颜色输出函数
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

function Info-Log($Message) { Write-ColorOutput Blue "[INFO] $Message" }
function Success-Log($Message) { Write-ColorOutput Green "[SUCCESS] $Message" }
function Warn-Log($Message) { Write-ColorOutput Yellow "[WARN] $Message" }
function Error-Log($Message) { Write-ColorOutput Red "[ERROR] $Message"; exit 1 }

# 远程仓库配置
$RepoUrl = "https://raw.githubusercontent.com/nideyeye/tomzang_plungin"
$RepoBranch = $env:REPO_BRANCH ?? "open-code"

# 获取脚本所在目录
$ScriptDir = Split-Path -Parent $PSScriptRoot
if (Test-Path variable:global:PSCommandPath) {
    $ScriptDir = Split-Path -Parent $global:PSCommandPath
}
$PluginFile = Join-Path $ScriptDir "index.js"

# OpenCode 配置路径
if ($IsWindows -or ($null -eq $IsWindows -and $env:OS -eq "Windows_NT")) {
    $OpenCodeConfigDir = Join-Path $env:USERPROFILE ".config" "opencode"
} else {
    $OpenCodeConfigDir = Join-Path $env:HOME ".config" "opencode"
}
$OpenCodeConfigFile = Join-Path $OpenCodeConfigDir "opencode.json"
$OpenCodePluginsDir = Join-Path $OpenCodeConfigDir "plugins"

# 临时目录
$TempDir = $null

# 清理函数
function Cleanup-TempFiles {
    if ($TempDir -and (Test-Path $TempDir)) {
        Remove-Item -Recurse -Force $TempDir -ErrorAction SilentlyContinue
        Info-Log "已清理临时文件"
    }
}

# 设置退出时清理
$CleanupAction = {
    Cleanup-TempFiles
}
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action $CleanupAction -ErrorAction SilentlyContinue

# 验证 URL 格式
function Test-UrlFormat {
    param([string]$Url)
    if ($Url -notmatch "^https?://") {
        Error-Log "无效的 URL 格式: $Url"
    }
}

# 验证配置
function Test-Config {
    if ($SkipValidation) {
        Warn-Log "跳过配置验证"
        return
    }

    Info-Log "验证配置..."

    if ([string]::IsNullOrEmpty($FirewallUrl)) {
        Warn-Log "未配置 firewallUrl，插件将仅运行在日志模式（无安全检测）"
    } else {
        Test-UrlFormat $FirewallUrl
    }

    if ([string]::IsNullOrEmpty($AuthKey)) {
        Warn-Log "未配置 authKey，插件将仅运行在日志模式（无安全检测）"
    }

    if ([string]::IsNullOrEmpty($FirewallUrl) -or [string]::IsNullOrEmpty($AuthKey)) {
        Warn-Log "如需启用防火墙功能，请配置 firewallUrl 和 authKey"
    }

    Success-Log "配置验证通过"
}

# 下载远程文件
function Get-RemoteFile {
    param(
        [string]$Url,
        [string]$Destination
    )

    $MaxRetries = 3
    $Retry = 0

    while ($Retry -lt $MaxRetries) {
        try {
            if ($IsWindows -or ($null -eq $IsWindows -and $env:OS -eq "Windows_NT")) {
                # Windows: 使用 Invoke-WebRequest
                Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -ErrorAction Stop
            } else {
                # Unix-like: 尝试使用 curl
                & curl -fsSL $Url -o $Destination 2>$null
                if ($LASTEXITCODE -ne 0) { throw "curl failed" }
            }
            return
        } catch {
            $Retry++
            if ($Retry -lt $MaxRetries) {
                Warn-Log "下载失败，重试 ($Retry/$MaxRetries)..."
                Start-Sleep -Seconds 1
            } else {
                Error-Log "无法下载文件: $Url"
            }
        }
    }
}

# 检查/下载必要文件
function Test-PluginFiles {
    Info-Log "检查必要文件..."

    # 检查是否需要远程下载
    if (-not (Test-Path $PluginFile)) {
        Warn-Log "本地插件文件不存在，尝试从远程下载..."

        # 创建临时目录
        $TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "opencode-plugin-$([Guid]::NewGuid())"
        New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
        Info-Log "创建临时目录: $TempDir"

        # 下载插件文件
        Info-Log "下载插件文件..."
        $PluginDownloadUrl = "$RepoUrl/$RepoBranch/index.js"
        Get-RemoteFile -Url $PluginDownloadUrl -Destination (Join-Path $TempDir "index.js")

        # 更新文件路径
        $script:PluginFile = Join-Path $TempDir "index.js"

        Success-Log "远程文件下载完成"
    }

    if (-not (Test-Path $PluginFile)) {
        Error-Log "插件文件不存在: $PluginFile"
    }

    Success-Log "必要文件检查通过"
}

# 构建插件配置 JSON
function Get-PluginConfig {
    param([string]$PluginPath = $PluginFile)

    $Config = [ordered]@{
        package = $PluginPath
        options = [ordered]@{
            firewallUrl = $FirewallUrl
            authKey = $AuthKey
            blockMessage = $BlockMessage
            firewallTimeout = $FirewallTimeout
            debug = $Debug.IsPresent
        }
    }
    return $Config
}

# 显示配置摘要
function Show-ConfigSummary {
    @"

==========================================
  OpenCode 插件安装脚本
  TomZang Firewall Plugin v1.0.0
==========================================

配置摘要:
  安装模式: $Mode
  项目目录: $ProjectDir
  防火墙 URL: $(if ($FirewallUrl) { $FirewallUrl } else { '<未配置，仅日志模式>' })
  认证密钥: $(if ($AuthKey) { '<已设置>' } else { '<未设置>' })
  拦截消息: $BlockMessage
  超时时间: ${FirewallTimeout}ms
  调试模式: $($Debug.IsPresent)

"@
}

# 项目级安装
function Install-ProjectLevel {
    param([string]$ProjectPath)

    $ConfigFile = Join-Path $ProjectPath "opencode.json"

    Info-Log "安装到项目: $ProjectPath"

    # 检查项目目录
    if (-not (Test-Path $ProjectPath)) {
        Error-Log "项目目录不存在: $ProjectPath"
    }

    # 确定插件路径
    $PluginPath = $PluginFile
    $NeedCopy = $false

    # 如果使用临时文件，复制到项目目录
    if ($TempDir -and $PluginFile -like "$TempDir*") {
        $NeedCopy = $true
        $TargetPluginDir = Join-Path $ProjectPath ".opencode-plugins" "tomzang_plungin"
        New-Item -ItemType Directory -Path $TargetPluginDir -Force | Out-Null

        Info-Log "复制插件文件到 $TargetPluginDir"
        Copy-Item -Path $PluginFile -Destination (Join-Path $TargetPluginDir "index.js") -Force

        $PluginPath = (Join-Path $TargetPluginDir "index.js") -replace "\\", "/"
    } else {
        # 本地文件路径，转换为正斜杠
        $PluginPath = $PluginFile -replace "\\", "/"
    }

    # 创建或更新 opencode.json
    if (Test-Path $ConfigFile) {
        Info-Log "已存在配置文件: $ConfigFile"
        Info-Log "将添加插件配置..."
        $ExistingConfig = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    } else {
        Info-Log "创建新配置文件: $ConfigFile"
        $ExistingConfig = @{ plugin = @() }
    }

    # 添加插件配置
    if (-not $ExistingConfig.plugin) {
        $ExistingConfig.plugin = @()
    }

    # 移除已存在的同名插件
    $ExistingConfig.plugin = $ExistingConfig.plugin | Where-Object {
        $_.package -notlike "*tomzang_plungin*"
    }

    # 添加新配置
    $PluginConfig = Get-PluginConfig -PluginPath $PluginPath
    $ExistingConfig.plugin += $PluginConfig

    # 保存配置
    $ExistingConfig | ConvertTo-Json -Depth 10 | Set-Content $ConfigFile

    Success-Log "项目级安装完成"
    Info-Log "配置文件: $ConfigFile"
    if ($NeedCopy) {
        Info-Log "插件文件已复制到: $PluginPath"
    }
}

# 全局级安装
function Install-GlobalLevel {
    Info-Log "安装到全局: $OpenCodePluginsDir"

    # 创建必要的目录
    New-Item -ItemType Directory -Path $OpenCodePluginsDir -Force | Out-Null

    # 复制插件文件
    $TargetPluginDir = Join-Path $OpenCodePluginsDir "tomzang_plungin"
    New-Item -ItemType Directory -Path $TargetPluginDir -Force | Out-Null

    Info-Log "复制插件文件到 $TargetPluginDir"
    Copy-Item -Path $PluginFile -Destination (Join-Path $TargetPluginDir "index.js") -Force

    # 创建或更新全局配置
    if (Test-Path $OpenCodeConfigFile) {
        Info-Log "已存在全局配置文件"
        Info-Log "将添加插件配置..."
        $ExistingConfig = Get-Content $OpenCodeConfigFile -Raw | ConvertFrom-Json
    } else {
        Info-Log "创建全局配置文件"
        New-Item -ItemType Directory -Path $OpenCodeConfigDir -Force | Out-Null
        $ExistingConfig = @{ plugin = @() }
    }

    # 添加插件配置
    if (-not $ExistingConfig.plugin) {
        $ExistingConfig.plugin = @()
    }

    # 移除已存在的同名插件
    $ExistingConfig.plugin = $ExistingConfig.plugin | Where-Object {
        $_.package -notlike "*tomzang_plungin*"
    }

    # 添加新配置
    $PluginPath = (Join-Path $TargetPluginDir "index.js") -replace "\\", "/"
    $PluginConfig = Get-PluginConfig -PluginPath $PluginPath
    $ExistingConfig.plugin += $PluginConfig

    # 保存配置
    $ExistingConfig | ConvertTo-Json -Depth 10 | Set-Content $OpenCodeConfigFile

    Success-Log "全局级安装完成"
    Info-Log "插件目录: $TargetPluginDir"
    Info-Log "配置文件: $OpenCodeConfigFile"
}

# 显示摘要
Show-ConfigSummary

# 检查必要文件
Test-PluginFiles

# 验证配置
Test-Config

# 执行安装
if ($Mode -eq "global") {
    Install-GlobalLevel
} else {
    Install-ProjectLevel -ProjectPath $ProjectDir
}

@"

$(Success-Log '安装完成！')
$(Info-Log '重启 OpenCode 以启用插件')

"@
