# ツール実行前の検査（PreToolUse）。1回の起動で次の5つをまとめて判定する
#   H2 認証情報・社外秘フォルダへのアクセス（block＝止める／warn＝通して注意）
#   H3 メール送信・Teams 投稿・ファイル共有などの外部への送信（ask＝確認を求める）
#   H4 Cloud Run への直接デプロイ（warn＝デプロイ受付の利用を促す／block＝止める）
#   H6 クラウド資源の削除・強制 push など取り返しのつかない操作（ask）
#   H7 誰でもアクセスできる状態にする公開（ask）
# 複数に当てはまるときは、止める＞確認を求める＞注意の順に強いほうを返す。
# 文字列の検査なので完全ではない（難読化されたコマンドは通る）。置き場所の対策・自動モード・デプロイ受付の検査と併用する
. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

try {
  $raw = Read-HookInput
  $tool = Get-JsonString $raw 'tool_name'
  if (-not $tool) { exit 0 }
  $isShell = ($tool -eq 'Bash' -or $tool -eq 'PowerShell')
  $isFile = @('Read', 'Edit', 'Write', 'NotebookEdit', 'Grep', 'Glob') -contains $tool

  # 検査するのはツールへの入力だけ（セッション ID・作業フォルダなどの付帯情報は除く）
  $body = [regex]::Replace($raw, '"(session_id|transcript_path|cwd|permission_mode|hook_event_name|prompt_id|agent_id|agent_type|effort|tool_use_id|tool_name)"\s*:\s*"(?:[^"\\]|\\.)*"', '')
  try { $body = [regex]::Unescape($body) } catch {}
  $text = $body.Replace('\', '/')
  $command = if ($isShell) { Get-JsonString $raw 'command' } else { '' }

  $denies = [System.Collections.Generic.List[string]]::new()
  $asks = [System.Collections.Generic.List[string]]::new()
  $warns = [System.Collections.Generic.List[string]]::new()
  function Add-Result([string]$mode, [string]$msg) {
    if ($mode -eq 'block') { $denies.Add($msg) }
    elseif ($mode -eq 'ask') { $asks.Add($msg) }
    elseif ($mode -eq 'warn') { $warns.Add($msg) }
  }

  # ---- H2 認証情報・社外秘フォルダ ----
  $m2 = Get-GuardMode 'H2'
  if ($m2 -ne 'off') {
    $h2 = $null
    if ($isFile) {
      $paths = ((Get-JsonString $raw 'file_path') + ' ' + (Get-JsonString $raw 'path') + ' ' + (Get-JsonString $raw 'notebook_path')).Replace('\', '/')
      if ([regex]::IsMatch($paths, '社外秘|極秘|部外秘|/Confidential/')) { $h2 = '社外秘フォルダ' }
    }
    if (-not $h2 -and ($isFile -or $isShell)) {
      $patterns = [ordered]@{
        '.env ファイル'            = '(^|[/"''\s\\=(])\.env([.''"\s\\)]|$)'
        'SSH 鍵'                   = '/\.ssh([/"''\s\\]|$)|id_rsa|id_ed25519'
        '証明書・秘密鍵'           = '\.(pem|key|pfx|p12)([''"\s\\)]|$)'
        'クラウドの認証情報'       = '/(\.aws|\.azure)([/"''\s\\]|$)|AppData/Roaming/gcloud|\.config/gcloud|\.clasprc\.json|application_default_credentials'
        'ブラウザの保存パスワード' = 'Login Data|/Cookies|/Local State'
        'Windows 資格情報'         = 'cmdkey\s+/list|Get-StoredCredential|vaultcmd'
      }
      foreach ($k in $patterns.Keys) { if ([regex]::IsMatch($text, $patterns[$k])) { $h2 = $k; break } }
    }
    if ($h2) {
      Write-GuardLog 'tool-guard' "H2-$m2" "$tool`t$h2"
      if ($m2 -eq 'block') { Add-Result 'block' "会社のセキュリティルールにより $tool の実行を止めました（対象：$h2）。このファイルは読まずに作業を続けてください。" }
      else { Add-Result 'warn' "注意（会社のセキュリティルール）：$tool が $h2 に触れようとしています。認証情報や社外秘の中身は表示・送信しないでください。" }
    }
  }

  # ---- H3 外部への送信（コネクタの送信系ツール） ----
  $m3 = Get-GuardMode 'H3'
  if ($m3 -ne 'off' -and $tool.StartsWith('mcp__') -and [regex]::IsMatch($tool, 'send|share|forward|reply|post|create_event|update_event|invite', 'IgnoreCase')) {
    $short = $tool.Substring($tool.LastIndexOf('__') + 2)
    $subject = Get-JsonString $raw 'subject'
    $detail = if ($subject) { "（件名：$subject）" } else { '' }
    Write-GuardLog 'tool-guard' "H3-$m3" "$tool"
    Add-Result $m3 "外部への送信です（$short）$detail。宛先・内容・添付を確認してから許可してください。"
  }

  if ($isShell -and $command) {
    # ---- H6 取り返しのつかない操作 ----
    $m6 = Get-GuardMode 'H6'
    if ($m6 -ne 'off') {
      $h6 = [ordered]@{
        'Google Cloud の資源の削除' = 'gcloud\s+(run\s+(services|jobs)|projects|sql\s+instances|storage\s+buckets|firestore\s+databases|secrets|functions|scheduler\s+jobs|artifacts\s+repositories)\s+delete'
        'バケットの中身の一括削除'  = 'gcloud\s+storage\s+rm\s+[^;&|\n]*(-r\b|--recursive)|gsutil\s+(-m\s+)?rm\s+-r'
        'Firestore の一括削除'      = 'firestore:delete'
        'git の強制 push'           = 'git\s+push\s+[^;&|\n]*(--force\b|--force-with-lease\b|-f\b)'
        'git の履歴の巻き戻し'      = 'git\s+reset\s+--hard'
        'データベースの削除'        = '\bDROP\s+(TABLE|DATABASE|SCHEMA)\b'
        'GitHub リポジトリの削除'   = 'gh\s+repo\s+delete'
      }
      foreach ($k in $h6.Keys) {
        if ([regex]::IsMatch($command, $h6[$k], 'IgnoreCase')) {
          Write-GuardLog 'tool-guard' "H6-$m6" "$k"
          Add-Result $m6 "$k です。実行すると元に戻せません。対象と影響を確認してから許可してください。"
          break
        }
      }
    }

    # ---- H7 全員への公開 ----
    $m7 = Get-GuardMode 'H7'
    if ($m7 -ne 'off' -and [regex]::IsMatch($command, '\ballUsers\b|allAuthenticatedUsers|--allow-unauthenticated|--no-invoker-iam-check|--visibility[ =]public|gh\s+repo\s+create\s+[^;&|\n]*--public', 'IgnoreCase')) {
      Write-GuardLog 'tool-guard' "H7-$m7" 'public'
      Add-Result $m7 '誰でもアクセスできる状態にする操作です。社内向けのアプリは Microsoft 365 サインインが必須です。意図した公開か確認してから許可してください。'
    }

    # ---- H4 Cloud Run への直接デプロイ ----
    $m4 = Get-GuardMode 'H4'
    if ($m4 -ne 'off' -and [regex]::IsMatch($command, 'gcloud\s+run\s+deploy|(^|[\s;&|(])(bash\s+|sh\s+|\./)deploy\.sh\b|clasp\s+(push|deploy)\b', 'IgnoreCase')) {
      Write-GuardLog 'tool-guard' "H4-$m4" 'deploy'
      if ($m4 -eq 'block') { Add-Result 'block' '本番・検証の Cloud Run へは、デプロイ受付（kusakabe-deploy）を通してデプロイしてください。直接のデプロイは会社のルールで止めています。' }
      else { Add-Result 'warn' 'お知らせ：会社のデプロイは、デプロイ受付（kusakabe-deploy）経由に移行中です。使える場合は受付経由でデプロイしてください（移行の完了後は、直接のデプロイは止まります）。' }
    }
  }

  if ($denies.Count -gt 0) {
    $r = $denies -join "`n"
    Write-HookJson ('{"systemMessage":' + (ConvertTo-JsonText $r) + ',"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":' + (ConvertTo-JsonText $r) + '}}')
  } elseif ($asks.Count -gt 0) {
    $r = '会社のセキュリティルールによる確認：' + ($asks -join ' ')
    $extra = if ($warns.Count -gt 0) { ',"systemMessage":' + (ConvertTo-JsonText ($warns -join "`n")) } else { '' }
    Write-HookJson ('{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":' + (ConvertTo-JsonText $r) + '}' + $extra + '}')
  } elseif ($warns.Count -gt 0) {
    $r = $warns -join "`n"
    Write-HookJson ('{"systemMessage":' + (ConvertTo-JsonText $r) + ',"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":' + (ConvertTo-JsonText $r) + '}}')
  }
  exit 0
} catch {
  exit 0
}
