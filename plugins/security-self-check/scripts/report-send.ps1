# R13：検知の記録（outbox.jsonl）を、管理者の監視画面（security-monitor）へまとめて送る（Stop・非同期）
# 送信先と受け取り専用のトークンは組織設定の env で渡す（このリポジトリは公開なので値は置かない）
#   KUSAKABE_GUARD_REPORT_URL   = https://<security-monitor>/api/guard-events
#   KUSAKABE_GUARD_REPORT_TOKEN = 受け取り専用のトークン（記録を送ることしかできない）
# 送るのは日時・利用者・PC 名・ルール・動作・ツール名・種類だけ。送れなかったときは次回にまとめて送る
. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
try {
  $url = [Environment]::GetEnvironmentVariable('KUSAKABE_GUARD_REPORT_URL')
  $token = [Environment]::GetEnvironmentVariable('KUSAKABE_GUARD_REPORT_TOKEN')
  # 送信先は https だけ（試験用に、この PC の中への http は通す）
  if (-not $url -or -not $token -or -not ($url.StartsWith('https://') -or $url -match '^http://(127\.0\.0\.1|localhost)[:/]')) { exit 0 }
  $dir = [IO.Path]::Combine($env:LOCALAPPDATA, 'ClaudeGuard')
  $outbox = [IO.Path]::Combine($dir, 'outbox.jsonl')
  $sending = [IO.Path]::Combine($dir, 'outbox.sending')
  if (-not [IO.File]::Exists($sending)) {
    if (-not [IO.File]::Exists($outbox)) { exit 0 }
    try { [IO.File]::Move($outbox, $sending) } catch { exit 0 }
  } elseif ([IO.File]::Exists($outbox)) {
    # 前回の送信が失敗して残っている。新しい記録を足して送り直す（受け取る側は同じ記録を1件として扱う）
    try { [IO.File]::AppendAllText($sending, [IO.File]::ReadAllText($outbox, $script:Utf8), $script:Utf8); [IO.File]::Delete($outbox) } catch {}
  }
  $lines = [System.Collections.Generic.List[string]]::new()
  foreach ($l in [IO.File]::ReadAllLines($sending, $script:Utf8)) { if ($l.Trim().StartsWith('{')) { $lines.Add($l.Trim()) } }
  if ($lines.Count -eq 0) { [IO.File]::Delete($sending); exit 0 }
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  # 1回に50件まで。多いときは何回かに分ける
  for ($i = 0; $i -lt $lines.Count; $i += 50) {
    $chunk = $lines.GetRange($i, [Math]::Min(50, $lines.Count - $i))
    $body = $script:Utf8.GetBytes('{"events":[' + ($chunk -join ',') + ']}')
    $req = [Net.HttpWebRequest]::Create($url)
    $req.Method = 'POST'; $req.ContentType = 'application/json; charset=utf-8'; $req.Timeout = 8000
    $req.Headers.Add('X-Guard-Token', $token)
    $req.ContentLength = $body.Length
    $s = $req.GetRequestStream(); $s.Write($body, 0, $body.Length); $s.Close()
    $res = $req.GetResponse(); $code = [int]$res.StatusCode; $res.Close()
    if ($code -lt 200 -or $code -ge 300) { exit 0 }
  }
  [IO.File]::Delete($sending)
} catch {}
exit 0
