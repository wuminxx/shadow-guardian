# scan.ps1 —— 测绘 AI 客户端在本机的落盘取证面（Windows）
# 用法: .\scan.ps1 [-Json]
[CmdletBinding()]
param([switch]$Json)

$ErrorActionPreference = 'SilentlyContinue'

$targets = @(
  "$env:USERPROFILE\.claude"
  "$env:USERPROFILE\.codex"
  "$env:USERPROFILE\.cursor"
  "$env:USERPROFILE\.continue"
  "$env:USERPROFILE\.aider"
  "$env:USERPROFILE\.ollama"
  "$env:USERPROFILE\.lmstudio"
  "$env:USERPROFILE\.cache\huggingface"
  "$env:APPDATA\Claude"
  "$env:APPDATA\Cursor"
  "$env:APPDATA\Code"
  "$env:APPDATA\aider"
  "$env:LOCALAPPDATA\Claude"
  "$env:LOCALAPPDATA\Programs\Claude"
  "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
  "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
  "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default"
)

# 高价值文件名特征
$hotPattern = '(?i)(history\.jsonl|\.jsonl$|\\memory(\\|$)|\\sessions?(\\|$)|\\projects?(\\|$)|transcripts?|\\todos(\\|$)|shell-snapshots|conversations?)'

function Get-Human {
  param([long]$Bytes)
  if ($Bytes -ge 1073741824) { '{0:N2} GB' -f ($Bytes / 1GB) }
  elseif ($Bytes -ge 1048576) { '{0:N2} MB' -f ($Bytes / 1MB) }
  elseif ($Bytes -ge 1024)    { '{0:N1} KB' -f ($Bytes / 1KB) }
  else { "$Bytes B" }
}

$rows = @()
$total = 0

foreach ($t in $targets) {
  if (-not (Test-Path $t)) { continue }
  $files = Get-ChildItem $t -Recurse -File -ErrorAction SilentlyContinue
  $bytes = ($files | Measure-Object Length -Sum).Sum
  if (-not $bytes) { $bytes = 0 }
  $total += $bytes

  $hot = $false
  if ($files | Where-Object { $_.FullName -match $hotPattern } | Select-Object -First 1) {
    $hot = $true
  }
  $rows += [pscustomobject]@{ Path = $t; Bytes = $bytes; Sensitive = $hot }
}

if ($Json) {
  $rows | ConvertTo-Json -Compress
  return
}

Write-Output "=== AI 客户端落盘测绘 ==="
Write-Output ("主机: {0}  用户: {1}  时间: {2}" -f $env:COMPUTERNAME, $env:USERNAME, (Get-Date -Format o))
Write-Output ""
Write-Output ("{0,14}  {1}" -f "大小", "路径")
Write-Output ("-" * 78)

foreach ($r in $rows) {
  $flag = if ($r.Sensitive) { "  <== 敏感落盘" } else { "" }
  Write-Output ("{0,14}  {1}{2}" -f (Get-Human $r.Bytes), $r.Path, $flag)
}

Write-Output ("-" * 78)
Write-Output ("命中目录: {0}    合计: {1}" -f $rows.Count, (Get-Human $total))
Write-Output ""
Write-Output "=== 高价值文件（明文会话/memory/snapshot）==="

foreach ($t in $targets) {
  if (-not (Test-Path $t)) { continue }
  Get-ChildItem $t -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match $hotPattern } |
    Select-Object -First 25 |
    ForEach-Object { Write-Output ("  {0}" -f $_.FullName) }
}

Write-Output ""
Write-Output "下一步:"
Write-Output "  1) 关遥测/memory: 见 docs/forensics-surface.md"
Write-Output "  2) 会话目录改用 VeraCrypt 容器"
Write-Output "  3) 清痕: .\scripts\shred.ps1"
