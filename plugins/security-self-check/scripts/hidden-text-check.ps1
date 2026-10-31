# スキル hidden-text-check から使う：受け取った文書・フォルダの隠し要素を一覧にする
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File hidden-text-check.ps1 -Path "<ファイルかフォルダ>"
# Word・Excel・PowerPoint・PDF：白い文字・極小の文字・非表示の文字／シート／行／スライド・コメント・ノート・プロパティ・マクロ
# HTML・Markdown・テキスト・メール等：見えない文字（Tag 文字・異体字セレクタの連続・双方向制御）・非表示の HTML やコメントの中の指示
# どちらも、AI への指示らしい文があれば示す。ファイルは読むだけで変更しない
param([Parameter(Mandatory = $true)][string]$Path)
. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, 'inspect-lib.ps1'))

$TextExts = @('.html', '.htm', '.md', '.mdc', '.txt', '.json', '.csv', '.xml', '.eml', '.svg', '.js', '.ts', '.py', '.ps1', '.yaml', '.yml', '.toml', '.ini', '.rtf')
$out = [System.Text.StringBuilder]::new()
$full = [IO.Path]::GetFullPath($Path)
$files = [System.Collections.Generic.List[string]]::new()
if ([IO.Directory]::Exists($full)) {
  foreach ($f in [IO.Directory]::GetFiles($full, '*', [IO.SearchOption]::AllDirectories)) {
    if ($f -match '[\\/](\.git|node_modules|\.venv|__pycache__)[\\/]') { continue }
    $e = [IO.Path]::GetExtension($f).ToLowerInvariant()
    if ($script:DocExts -contains $e -or $TextExts -contains $e) { $files.Add($f) }
    if ($files.Count -ge 500) { break }
  }
} elseif ([IO.File]::Exists($full)) { $files.Add($full) }
else { Write-HookJson "見つかりません：$full`n"; exit 1 }

$n = 0
foreach ($f in $files) {
  $e = [IO.Path]::GetExtension($f).ToLowerInvariant()
  $list = [System.Collections.Generic.List[string]]::new()
  try {
    if ($script:DocExts -contains $e) { foreach ($x in (Get-DocumentFindings $f)) { $list.Add($x) } }
    elseif (([IO.FileInfo]::new($f)).Length -le 5MB) {
      $t = [IO.File]::ReadAllText($f, $script:Utf8)
      foreach ($x in (Get-TextFindings $t)) { $list.Add($x) }
      $i = Find-Instruction $t
      if ($i -and $list.Count -eq 0) { $list.Add("見える文字の中に AI への指示らしい文：「$i」（説明文なら問題なし）") }
    }
  } catch { $list.Add("調べられませんでした（$($_.Exception.Message)）") }
  if ($list.Count -gt 0) {
    $n++
    [void]$out.AppendLine("■ $($f.Substring([Math]::Min($f.Length, ([IO.Path]::GetDirectoryName($full)).Length)).TrimStart('\'))")
    foreach ($x in $list) { [void]$out.AppendLine("  - $x") }
  }
}
$head = "対象：$full（$($files.Count) ファイル）`n"
if ($n -eq 0) { $head += "隠し要素・隠れた指示は見つかりませんでした。`n" } else { $head += "隠し要素・隠れた指示があったファイル：$n 件`n" }
Write-HookJson ($head + $out.ToString())
