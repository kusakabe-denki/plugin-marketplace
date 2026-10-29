# H5：プロジェクトの秘密情報の置き場所を自己チェックする
#   フックとして（SessionStart）：開いたプロジェクトを1日1回、短時間でスキャンし、見つかれば利用者と Claude に知らせる
#   スキルから（-Full -ProjectDir <フォルダ>）：時間の制限なしで全件を一覧にする
# 検出するもの（秘密の値そのものは表示しない）:
#   - .env ファイルに書かれた秘密情報（KEY・TOKEN・SECRET・PASSWORD 等の名前で値があるもの）
#   - ~/.clasprc.json（clasp のトークン）を読むコード
#   - コードに直書きされた API キー・トークン・秘密鍵
#   - サービスアカウントの鍵ファイル（"private_key" を含む JSON）
param([string]$DataDir = '', [switch]$Full, [string]$ProjectDir = '')
. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

$SkipDirs = @('.git', 'node_modules', '.venv', 'venv', 'env', '__pycache__', 'dist', 'build', '.next', 'out', 'target', '.terraform', 'vendor', '.cache', 'coverage', '.idea', '.vscode')
$CodeExt = @('.py', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.gs', '.sh', '.ps1', '.psm1', '.bat', '.cmd', '.rb', '.go', '.java', '.cs', '.php', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.json', '.html', '.txt', '.md', '.dockerfile', '')
$MaxFiles = 4000; $MaxBytes = 512KB
$Deadline = if ($Full) { [DateTime]::MaxValue } else { [DateTime]::Now.AddSeconds(3) }

$KeyPatterns = [ordered]@{
  'Google の API キー'        = 'AIza[0-9A-Za-z_\-]{35}'
  'GitHub のトークン'         = 'gh[pousr]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{40,}'
  'OpenAI・Anthropic のキー'  = 'sk-(ant-|proj-)?[0-9A-Za-z_\-]{20,}'
  'Slack のトークン'          = 'xox[baprs]-[0-9A-Za-z\-]{10,}'
  'AWS のアクセスキー'        = 'AKIA[0-9A-Z]{16}'
  '秘密鍵'                    = '-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'
}

function Get-Findings([string]$root) {
  $found = [System.Collections.Generic.List[string]]::new()
  $count = 0; $truncated = $false
  $stack = [System.Collections.Generic.Stack[string]]::new(); $stack.Push($root)
  while ($stack.Count -gt 0) {
    if ([DateTime]::Now -gt $Deadline -or $count -ge $MaxFiles -and -not $Full) { $truncated = $true; break }
    $dir = $stack.Pop()
    try { $subs = [IO.Directory]::GetDirectories($dir) } catch { $subs = @() }
    foreach ($s in $subs) { if ($SkipDirs -notcontains [IO.Path]::GetFileName($s)) { $stack.Push($s) } }
    try { $files = [IO.Directory]::GetFiles($dir) } catch { $files = @() }
    foreach ($f in $files) {
      $count++
      $name = [IO.Path]::GetFileName($f)
      $rel = $f.Substring($root.Length).TrimStart('\', '/')
      $ext = [IO.Path]::GetExtension($f).ToLowerInvariant()
      try { $len = ([IO.FileInfo]::new($f)).Length } catch { continue }
      if ($len -gt $MaxBytes) { continue }
      $isEnv = [regex]::IsMatch($name, '^\.env(\.[\w-]+)?$') -and -not [regex]::IsMatch($name, '\.(example|sample|template|dist)$', 'IgnoreCase')
      if (-not $isEnv -and $CodeExt -notcontains $ext -and $name -ne 'Dockerfile') { continue }
      try { $lines = [IO.File]::ReadAllLines($f, $script:Utf8) } catch { continue }
      if ($isEnv) {
        for ($i = 0; $i -lt $lines.Length; $i++) {
          if ([regex]::IsMatch($lines[$i], '^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_]*(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL)[A-Za-z0-9_]*\s*=\s*\S', 'IgnoreCase')) {
            $found.Add("$rel`:$($i + 1)`t.env に秘密情報"); break
          }
        }
        continue
      }
      if ($ext -eq '.json' -and $lines.Length -lt 40 -and (($lines -join "`n") -match '"private_key"\s*:\s*"-----BEGIN')) { $found.Add("$rel`:1`tサービスアカウントの鍵ファイル"); continue }
      for ($i = 0; $i -lt $lines.Length; $i++) {
        $line = $lines[$i]
        if ($line.Length -gt 2000) { continue }
        if ($line.Contains('.clasprc.json') -and $ext -ne '.md' -and $ext -ne '.txt') { $found.Add("$rel`:$($i + 1)`tclasp のトークン（~/.clasprc.json）を読んでいる"); continue }
        foreach ($k in $KeyPatterns.Keys) {
          if ([regex]::IsMatch($line, $KeyPatterns[$k])) { $found.Add("$rel`:$($i + 1)`t$k（直書き）"); break }
        }
      }
      if ($found.Count -ge 50) { $truncated = $true; return @{ items = $found; truncated = $truncated } }
    }
  }
  return @{ items = $found; truncated = $truncated }
}

try {
  if ($Full) {
    $root = if ($ProjectDir) { [IO.Path]::GetFullPath($ProjectDir) } else { [IO.Directory]::GetCurrentDirectory() }
    $r = Get-Findings $root
    $out = [System.Text.StringBuilder]::new()
    [void]$out.AppendLine("対象：$root")
    if ($r.items.Count -eq 0) { [void]$out.AppendLine('要修正の箇所は見つかりませんでした。') }
    else {
      [void]$out.AppendLine("要修正の箇所：$($r.items.Count) 件（秘密の値は表示していません）")
      foreach ($x in $r.items) { $p = $x.Split("`t"); [void]$out.AppendLine("- $($p[1])：$($p[0])") }
      if ($r.truncated) { [void]$out.AppendLine('（件数が多いため途中までです）') }
    }
    Write-HookJson $out.ToString()
    exit 0
  }

  if ((Get-GuardMode 'H5') -eq 'off') { exit 0 }
  $raw = Read-HookInput
  $source = Get-JsonString $raw 'source'
  if ($source -and $source -ne 'startup' -and $source -ne 'resume') { exit 0 }
  $root = $env:CLAUDE_PROJECT_DIR
  if (-not $root) { $root = Get-JsonString $raw 'cwd' }
  if (-not $root -or -not [IO.Directory]::Exists($root)) { exit 0 }
  $root = [IO.Path]::GetFullPath($root).TrimEnd('\', '/')
  # ホームフォルダやドライブ直下は範囲が広すぎるので調べない
  if ($root -eq $env:USERPROFILE.TrimEnd('\') -or $root.Length -le 3) { exit 0 }

  # 同じプロジェクトは1日1回だけ
  if (-not $DataDir) { $DataDir = [IO.Path]::Combine($env:LOCALAPPDATA, 'ClaudeGuard') }
  $stampDir = [IO.Path]::Combine($DataDir, 'selfcheck'); [void][IO.Directory]::CreateDirectory($stampDir)
  $hash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($script:Utf8.GetBytes($root.ToLowerInvariant()))).Replace('-', '').Substring(0, 16)
  $stamp = [IO.Path]::Combine($stampDir, "$hash.txt")
  $today = [DateTime]::Now.ToString('yyyy-MM-dd')
  if ([IO.File]::Exists($stamp) -and ([IO.File]::ReadAllText($stamp).Trim() -eq $today)) { exit 0 }
  [IO.File]::WriteAllText($stamp, $today)

  $r = Get-Findings $root
  if ($r.items.Count -eq 0) { exit 0 }
  Write-GuardLog 'self-check' 'found' "$root`t$($r.items.Count)"
  $kinds = [System.Collections.Generic.HashSet[string]]::new()
  foreach ($x in $r.items) { [void]$kinds.Add($x.Split("`t")[1]) }
  $msg = "お知らせ（会社のセキュリティルール）：このプロジェクトに要修正の箇所が $($r.items.Count) 件あります（$(@($kinds) -join '、')）。「セキュリティの自己チェックをして」と頼むと、Secret Manager などへの移行を手伝います。"
  $lines = [System.Collections.Generic.List[string]]::new()
  for ($i = 0; $i -lt [Math]::Min(20, $r.items.Count); $i++) { $p = $r.items[$i].Split("`t"); $lines.Add("- $($p[1])：$($p[0])") }
  $list = $lines -join "`n"
  $ctx = "会社のセキュリティルールの自己チェック（security-self-check）で、このプロジェクトに要修正の箇所が見つかった。秘密情報はコード・.env に置かず Secret Manager に移し、API はサービスアカウントの IAM 権限で呼ぶのが会社のルール。キーの再発行は利用者の指示がない限りしない。利用者に知らせ、了解を得てから security-self-check スキルの手順で直すこと。`n$list"
  Write-HookJson ('{"systemMessage":' + (ConvertTo-JsonText $msg) + ',"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":' + (ConvertTo-JsonText $ctx) + '}}')
  exit 0
} catch {
  exit 0
}
