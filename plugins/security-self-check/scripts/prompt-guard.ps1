# H1：プロンプト送信前に、個人情報・社外秘を含むものを止める（UserPromptSubmit）
# 判定する内容:
#   - マイナンバー（12桁目の検査用数字が正しいもの）
#   - クレジットカード番号（Luhn 方式の検査が正しい16桁）
#   - 「社外秘」「極秘」などの表示
#   - blocked-words.txt に登録した語（未発表の案件コード等。1行1語）
#   - 社外のメールアドレス・電話番号が合計3件以上（名簿の貼り付けとみなす。同じものは1件と数える）
# 誤検知を減らすため、URL の中の文字は判定せず、社内ドメインのメールアドレスは数えない。
# 動作（common.ps1 の段階設定）: block＝止める／warn＝通して注意を伝える／off＝何もしない
# 止める段階でも、先頭に「#確認済」を付ければ送れる（記録が残る）
. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

# 社内ドメイン（サブドメインを含む）。社内のメールアドレスは名簿の判定に数えない
$InternalDomains = @('kusakabe.com')

function Test-MyNumber([string]$digits) {
  $total = 0
  for ($i = 0; $i -lt 11; $i++) {
    $q = if ($i -lt 6) { $i + 2 } else { $i - 4 }
    $total += ([int][string]$digits[10 - $i]) * $q
  }
  $r = $total % 11
  $check = if ($r -le 1) { 0 } else { 11 - $r }
  return ([int][string]$digits[11]) -eq $check
}

function Test-Luhn([string]$digits) {
  $sum = 0; $alt = $false
  for ($i = $digits.Length - 1; $i -ge 0; $i--) {
    $n = [int][string]$digits[$i]
    if ($alt) { $n *= 2; if ($n -gt 9) { $n -= 9 } }
    $sum += $n; $alt = -not $alt
  }
  return ($sum % 10) -eq 0
}

try {
  $mode = Get-GuardMode 'H1'
  if ($mode -eq 'off') { exit 0 }
  $prompt = Get-JsonString (Read-HookInput) 'prompt'
  if ([string]::IsNullOrWhiteSpace($prompt)) { exit 0 }
  if ($prompt.TrimStart().StartsWith('#確認済')) { Write-GuardLog 'prompt-guard' 'override' "$($prompt.Length)文字"; exit 0 }

  # URL の中は判定しない（Cloud Run の URL に含まれる12桁のプロジェクト番号などを除くため）
  $text = [regex]::Replace($prompt, 'https?://\S+', ' ')
  $hits = [System.Collections.Generic.List[string]]::new()

  foreach ($m in [regex]::Matches($text, '(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?![ -]?\d)')) {
    if (Test-MyNumber ([regex]::Replace($m.Value, '\D', ''))) { $hits.Add('マイナンバー'); break }
  }
  foreach ($m in [regex]::Matches($text, '(?<!\d)(?:\d{4}[ -]?){3}\d{4}(?!\d)')) {
    if (Test-Luhn ([regex]::Replace($m.Value, '\D', ''))) { $hits.Add('クレジットカード番号'); break }
  }
  if ([regex]::IsMatch($text, '社外秘|極秘|部外秘|Confidential')) { $hits.Add('「社外秘」等の表示') }

  $wordFile = [IO.Path]::Combine($PSScriptRoot, 'blocked-words.txt')
  if ([IO.File]::Exists($wordFile)) {
    foreach ($w in [IO.File]::ReadAllLines($wordFile, $script:Utf8)) {
      $w = $w.Trim()
      if ($w -and -not $w.StartsWith('#') -and $prompt.Contains($w)) { $hits.Add("登録語「$w」") }
    }
  }

  $escaped = @(); foreach ($d in $InternalDomains) { $escaped += [regex]::Escape($d) }
  $internal = '@([A-Za-z0-9-]+\.)*(' + ($escaped -join '|') + ')$'
  $contacts = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($m in [regex]::Matches($text, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')) {
    if (-not [regex]::IsMatch($m.Value, $internal, 'IgnoreCase')) { [void]$contacts.Add($m.Value) }
  }
  foreach ($m in [regex]::Matches($text, '(?<!\d)0\d{1,4}-\d{1,4}-\d{3,4}(?!\d)|(?<!\d)0[789]0\d{8}(?!\d)')) {
    [void]$contacts.Add([regex]::Replace($m.Value, '\D', ''))
  }
  if ($contacts.Count -ge 3) { $hits.Add("社外のメールアドレス・電話番号 $($contacts.Count) 件（名簿の貼り付けの可能性）") }

  if ($hits.Count -eq 0) { exit 0 }
  $found = $hits -join '、'

  if ($mode -eq 'block') {
    Write-GuardLog 'prompt-guard' 'blocked' ($hits -join ' / ')
    $reason = "送信を止めました（会社のセキュリティルール）：$found。`n個人情報・機密情報は伏せ字やダミーに置き換えてから送ってください。誤検知の場合は先頭に「#確認済」を付けて送れます（記録されます）。"
    Write-HookJson ('{"decision":"block","reason":' + (ConvertTo-JsonText $reason) + ',"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","suppressOriginalPrompt":true}}')
    exit 0
  }

  # warn：送信は通し、社員と Claude の両方に注意を伝える
  Write-GuardLog 'prompt-guard' 'warned' ($hits -join ' / ')
  $msg = "注意（会社のセキュリティルール）：このプロンプトに $found が含まれている可能性があります。個人情報・機密情報は伏せ字やダミーに置き換えるのが原則です。"
  $ctx = "会社のセキュリティルールの注意：利用者のプロンプトに $found が含まれている可能性がある。これらの情報を外部サービス・公開ページ・コミット・ログに含めないこと。必要なら利用者に伏せ字やダミーへの置き換えを提案すること。"
  Write-HookJson ('{"systemMessage":' + (ConvertTo-JsonText $msg) + ',"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":' + (ConvertTo-JsonText $ctx) + '}}')
  exit 0
} catch {
  exit 0
}
