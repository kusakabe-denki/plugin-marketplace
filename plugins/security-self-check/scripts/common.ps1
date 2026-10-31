# security-self-check の各フックで共通に使う部品（各スクリプトから . で読み込む）
# 速さのため、PowerShell のコマンドレット（初回の読み込みに約1.5秒かかる）は使わず .NET の機能だけで書く
$ErrorActionPreference = 'Stop'
$script:Utf8 = [System.Text.UTF8Encoding]::new($false)

# 段階ごとの既定の動作。組織設定の env で切り替える
#   KUSAKABE_GUARD_STAGE = 1（試行・既定）／2（本番）
#   KUSAKABE_GUARD_H1〜H12 = block / ask / warn / on / off で個別に上書き
$script:StageModes = @{
  '1' = @{ H1 = 'warn';  H2 = 'warn';  H3 = 'off'; H4 = 'warn'; H5 = 'on'; H6 = 'off'; H7 = 'off'; H8 = 'on';    H9 = 'warn'; H10 = 'warn'; H11 = 'warn'; H12 = 'on' }
  '2' = @{ H1 = 'block'; H2 = 'block'; H3 = 'ask'; H4 = 'warn'; H5 = 'on'; H6 = 'ask'; H7 = 'ask'; H8 = 'block'; H9 = 'warn'; H10 = 'ask';  H11 = 'ask';  H12 = 'on' }
}

function Get-GuardMode([string]$id) {
  $v = [Environment]::GetEnvironmentVariable("KUSAKABE_GUARD_$id")
  if ($v) { return $v.Trim().ToLowerInvariant() }
  $stage = [Environment]::GetEnvironmentVariable('KUSAKABE_GUARD_STAGE')
  if (-not $script:StageModes.ContainsKey("$stage")) { $stage = '1' }
  return $script:StageModes["$stage"][$id]
}

# 標準入力（フックに渡される JSON）を UTF-8 で読む
function Read-HookInput {
  try { return [IO.StreamReader]::new([Console]::OpenStandardInput(), $script:Utf8).ReadToEnd() } catch { return '' }
}

# JSON から文字列の項目を1つ取り出す（ConvertFrom-Json は初回の読み込みが遅いため使わない）
function Get-JsonString([string]$json, [string]$key) {
  $m = [regex]::Match($json, '"' + [regex]::Escape($key) + '"\s*:\s*"((?:[^"\\]|\\.)*)"')
  if (-not $m.Success) { return '' }
  try { return [regex]::Unescape($m.Groups[1].Value) } catch { return $m.Groups[1].Value }
}

# 文字列を JSON の文字列として書く
function ConvertTo-JsonText([string]$s) {
  $sb = [System.Text.StringBuilder]::new('"')
  foreach ($c in $s.ToCharArray()) {
    $n = [int]$c
    if ($c -eq '"') { [void]$sb.Append('\"') }
    elseif ($c -eq '\') { [void]$sb.Append('\\') }
    elseif ($n -eq 10) { [void]$sb.Append('\n') }
    elseif ($n -eq 13) { [void]$sb.Append('\r') }
    elseif ($n -eq 9) { [void]$sb.Append('\t') }
    elseif ($n -lt 32) { [void]$sb.Append(('\u{0:x4}' -f $n)) }
    else { [void]$sb.Append($c) }
  }
  [void]$sb.Append('"')
  return $sb.ToString()
}

# 結果の JSON を標準出力に UTF-8 で書く
function Write-HookJson([string]$json) {
  $b = $script:Utf8.GetBytes($json)
  $o = [Console]::OpenStandardOutput(); $o.Write($b, 0, $b.Length); $o.Flush()
}

# 各PCの %LOCALAPPDATA%\ClaudeGuard\<name>.log に記録する（失敗しても作業は止めない）
function Write-GuardLog([string]$name, [string]$kind, [string]$detail) {
  try {
    $dir = [IO.Path]::Combine($env:LOCALAPPDATA, 'ClaudeGuard')
    [void][IO.Directory]::CreateDirectory($dir)
    $line = "{0}`t{1}`t{2}`t{3}`r`n" -f [DateTime]::Now.ToString('s'), $env:USERNAME, $kind, $detail
    [IO.File]::AppendAllText([IO.Path]::Combine($dir, "$name.log"), $line, $script:Utf8)
  } catch {}
}

# 管理者の監視画面（security-monitor）へ送る検知を、送信待ちの記録（outbox.jsonl）に足す。送るのは report-send.ps1（Stop・非同期）
# 送るのは日時・利用者・PC 名・ルール・動作・ツール名・種類だけで、ファイルや結果の中身は入れない。
# 送信先（KUSAKABE_GUARD_REPORT_URL）が組織設定にないときは何もしない
function Write-GuardEvent([string]$rule, [string]$mode, [string]$tool, [string]$detail) {
  try {
    if (-not [Environment]::GetEnvironmentVariable('KUSAKABE_GUARD_REPORT_URL')) { return }
    $dir = [IO.Path]::Combine($env:LOCALAPPDATA, 'ClaudeGuard')
    [void][IO.Directory]::CreateDirectory($dir)
    $path = [IO.Path]::Combine($dir, 'outbox.jsonl')
    if ([IO.File]::Exists($path) -and ([IO.FileInfo]::new($path)).Length -gt 1MB) { return }
    if ($detail.Length -gt 200) { $detail = $detail.Substring(0, 200) }
    $line = '{"ts":' + (ConvertTo-JsonText ([DateTimeOffset]::Now.ToString('o'))) + ',"user":' + (ConvertTo-JsonText "$env:USERNAME") +
      ',"host":' + (ConvertTo-JsonText "$env:COMPUTERNAME") + ',"rule":' + (ConvertTo-JsonText $rule) + ',"mode":' + (ConvertTo-JsonText $mode) +
      ',"tool":' + (ConvertTo-JsonText $tool) + ',"detail":' + (ConvertTo-JsonText $detail) + "}`n"
    [IO.File]::AppendAllText($path, $line, $script:Utf8)
  } catch {}
}
