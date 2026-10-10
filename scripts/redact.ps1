# redact.ps1 —— 剥离文本中的身份字段（Windows）
# 用法:
#   Get-Content app.log -Raw | .\redact.ps1
#   .\redact.ps1 -File app.log -Out clean.log
[CmdletBinding()]
param(
  [string]$File,
  [string]$Out,
  [string]$Text
)

$rules = @(
  # 路径中的用户名
  @{ p = '(?i)([\\/]Users[\\/])[^\\/]+'; r = '$1USER' }
  @{ p = '(?i)(/home/)[^/]+';            r = '$1USER' }

  # 内网 IP
  @{ p = '\b(10\.\d{1,3}|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b'; r = '10.0.0.0' }

  # 邮箱
  @{ p = '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'; r = 'EMAIL@REDACTED' }

  # 中国大陆手机号
  @{ p = '\b1[3-9]\d{9}\b'; r = 'PHONE_REDACTED' }

  # 中国大陆身份证号
  @{ p = '\b[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b'; r = 'IDNUM_REDACTED' }

  # 常见 token 前缀
  @{ p = '(sk-ant-|sk-|ghp_|gho_|ghu_|ghs_|github_pat_|AKIA|AIza|xox[baprs]-|glpat-|hf_)[A-Za-z0-9_\-]{8,}'; r = 'TOKEN_REDACTED' }

  # 键值对形式的密钥
  @{ p = '(?i)(Bearer|token|secret|password|passwd|pwd|apikey|api_key)(["'':= ]+)[A-Za-z0-9_\-\.]{6,}'; r = '$1$2SECRET_REDACTED' }

  # 内部主机名
  @{ p = '\b[a-z0-9-]+\.(internal|local|corp|lan|intra|intranet)\b'; r = 'HOST.internal' }

  # PEM 私钥
  @{ p = '(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----'; r = '-----BEGIN PRIVATE KEY-----REDACTED-----END PRIVATE KEY-----' }
)

function Invoke-Redact {
  param([string]$InputText)
  $result = $InputText
  foreach ($rule in $rules) {
    $result = [regex]::Replace($result, $rule.p, $rule.r)
  }
  return $result
}

if ($Text) {
  Invoke-Redact -InputText $Text
} elseif ($File) {
  if (-not (Test-Path $File)) { Write-Error "文件不存在: $File"; exit 1 }
  $raw = Get-Content $File -Raw -Encoding UTF8
  $clean = Invoke-Redact -InputText $raw
  if ($Out) { [System.IO.File]::WriteAllText($Out, $clean, [System.Text.UTF8Encoding]::new($false)); Write-Host "已写入: $Out" }
  else { Write-Output $clean }
} else {
  # 从管道读
  $raw = [Console]::In.ReadToEnd()
  Invoke-Redact -InputText $raw
}
