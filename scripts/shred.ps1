# shred.ps1 —— 清除 AI 客户端在 Windows 上的会话痕迹
#
# 用法:
#   .\shred.ps1                  # DRY-RUN（只列出）
#   .\shred.ps1 -Force           # 真删
#   .\shred.ps1 -Force -IncludeConfig
#
# 警告: SSD + TRIM + CoW 文件系统下，原地覆写不保证擦除旧块。
#       真需要彻底时上 BitLocker/VeraCrypt + 一次性 VM。
[CmdletBinding()]
param(
  [switch]$Force,
  [switch]$IncludeConfig,
  [int]$Passes = 3
)

$ErrorActionPreference = 'SilentlyContinue'
$dry = -not $Force

$sessionTargets = @(
  "$env:USERPROFILE\.claude\projects"
  "$env:USERPROFILE\.claude\todos"
  "$env:USERPROFILE\.claude\shell-snapshots"
  "$env:USERPROFILE\.claude\statsig"
  "$env:USERPROFILE\.codex\sessions"
  "$env:USERPROFILE\.cursor\logs"
  "$env:USERPROFILE\.cursor\User\History"
  "$env:USERPROFILE\.continue\sessions"
)

$fileTargets = @(
  "$env:USERPROFILE\.claude\history.jsonl"
  "$env:USERPROFILE\.codex\history.jsonl"
  "$env:USERPROFILE\.aider\analytics.jsonl"
)

$configTargets = @(
  "$env:USERPROFILE\.claude\settings.json"
  "$env:USERPROFILE\.codex\config.toml"
)

function Remove-Secure {
  param([string]$Path, [int]$P)
  if (-not (Test-Path $Path)) { return }
  $fi = New-Object System.IO.FileInfo $Path
  $len = $fi.Length
  if ($len -gt 0) {
    try {
      $fs = [System.IO.File]::Open($Path, 'Open', 'ReadWrite')
      $buf = New-Object byte[] 1048576
      $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
      for ($pass = 0; $pass -lt $P; $pass++) {
        $fs.Position = 0
        $remaining = $len
        while ($remaining -gt 0) {
          $chunk = [Math]::Min($buf.Length, $remaining)
          $rng.GetBytes($buf, 0, $chunk)
          $fs.Write($buf, 0, $chunk)
          $remaining -= $chunk
        }
        $fs.Flush($true)
      }
      $fs.Close()
    } catch { }
  }
  Remove-Item $Path -Force -ErrorAction SilentlyContinue
}

function Show-Human {
  param([long]$B)
  if ($B -ge 1073741824) { '{0:N2} GB' -f ($B/1GB) }
  elseif ($B -ge 1048576) { '{0:N2} MB' -f ($B/1MB) }
  elseif ($B -ge 1024)    { '{0:N1} KB' -f ($B/1KB) }
  else { "$B B" }
}

Write-Output "=== AI 会话痕迹清理 (Windows) ==="
Write-Output ("模式: {0}" -f $(if ($dry) { 'DRY-RUN（只列出）' } else { 'FORCE（真删）' }))
Write-Output ("保留配置: {0}" -f $(if ($IncludeConfig) { '否' } else { '是' }))
Write-Output ("覆写遍数: {0}" -f $Passes)
Write-Output ""

$nf = 0; $nb = 0

function Invoke-Wipe {
  param([string]$Path)
  if (-not (Test-Path $Path)) { return }
  if ((Get-Item $Path).PSIsContainer) {
    $files = Get-ChildItem $Path -Recurse -File -ErrorAction SilentlyContinue
    $cnt = @($files).Count
    $sz = ($files | Measure-Object Length -Sum).Sum
    if (-not $sz) { $sz = 0 }
    Write-Output ("{0,8} files  {1,12}  {2}" -f $cnt, (Show-Human $sz), $Path)
    $script:nf += $cnt; $script:nb += $sz
    if (-not $dry) {
      foreach ($f in $files) { Remove-Secure -Path $f.FullName -P $Passes }
      Get-ChildItem $Path -Recurse -Directory -ErrorAction SilentlyContinue |
        Sort-Object { $_.FullName.Length } -Descending |
        ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }
      Remove-Item $Path -Force -Recurse -ErrorAction SilentlyContinue
    }
  } else {
    $sz = (Get-Item $Path).Length
    Write-Output ("{0,8}        {1,12}  {2}" -f 1, (Show-Human $sz), $Path)
    $script:nf += 1; $script:nb += $sz
    if (-not $dry) { Remove-Secure -Path $Path -P $Passes }
  }
}

foreach ($t in $sessionTargets) { Invoke-Wipe $t }

# 单文件：单列，清空即保留文件
foreach ($f in $fileTargets) {
  if (-not (Test-Path $f)) { continue }
  $sz = (Get-Item $f).Length
  Write-Output ("{0,8}        {1,12}  {2}" -f "清空", (Show-Human $sz), $f)
  $script:nf += 1; $script:nb += $sz
  if (-not $dry) {
    Remove-Secure -Path $f -P $Passes
    [System.IO.File]::WriteAllText($f, '')
  }
}

if ($IncludeConfig) {
  Write-Output ""
  Write-Output "--- 配置（-IncludeConfig 生效）---"
  foreach ($t in $configTargets) { Invoke-Wipe $t }
}

Write-Output ""
Write-Output ("-" * 40)
Write-Output ("合计: {0} 项  {1}" -f $nf, (Show-Human $nb))

if ($dry) {
  Write-Output ""
  Write-Output "这是 DRY-RUN。要真删跑: .\shred.ps1 -Force"
} else {
  Write-Output ""
  Write-Output "已清理。注意: SSD/CoW 下覆写不保证擦除旧块。"
  Write-Output "彻底方案: BitLocker/VeraCrypt + 一次性 VM。"
}
