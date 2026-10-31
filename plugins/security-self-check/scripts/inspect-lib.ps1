# 取り込んだ内容・文書・リポジトリの設定ファイルに隠された指示を調べる部品
# H9（取り込んだ内容の検査）・H12（リポジトリの罠）・スキル hidden-text-check から . で読み込む（先に common.ps1 を読み込むこと）
# 速さのため、PowerShell のコマンドレットは使わず .NET の機能だけで書く

# ---- 見えない文字 ----
# Tag 文字 U+E0000〜E007F（ASCII スマグリング。画面には見えないがモデルには読める）
$script:TagRe = [regex]::new('\uDB40[\uDC00-\uDC7F]')
# 異体字セレクタの連続（絵文字に情報を隠す手口）。漢字の異体字（IVS）は1文字なので、2文字以上の連続だけを対象にする
$script:VsRunRe = [regex]::new('(?:[\uFE00-\uFE0E]|\uDB40[\uDD00-\uDDEF]){2,}')
# 双方向制御文字（表示とモデルが読む順番を食い違わせる）
$script:BidiRe = [regex]::new('[\u202A-\u202E\u2066-\u2069]')
# ゼロ幅の文字（メールの余白埋めなど正常な用途も多いので、除去するが警告はしない）。行頭・文字列の先頭の BOM は除く
$script:ZeroWidthRe = [regex]::new('[\u200B-\u200F\u2060-\u2064\u180E]|(?<!^|\\[nt]|["\n\t])\uFEFF')

# 文字列に含まれる見えない文字を種類ごとに数える。Tag 文字は隠れていた ASCII の文を復元する
function Get-HiddenCharReport([string]$s) {
  $r = @{ tag = 0; tagText = ''; vs = 0; bidi = 0; zw = 0 }
  if (-not $s) { return $r }
  $m = $script:TagRe.Matches($s)
  $r.tag = $m.Count
  if ($m.Count -gt 0) {
    $sb = [System.Text.StringBuilder]::new()
    foreach ($x in $m) {
      $c = [int]$x.Value[1] - 0xDC00
      if ($c -ge 0x20 -and $c -lt 0x7F) { [void]$sb.Append([char]$c) }
      if ($sb.Length -ge 120) { break }
    }
    $r.tagText = $sb.ToString().Trim()
  }
  $r.vs = $script:VsRunRe.Matches($s).Count
  $r.bidi = $script:BidiRe.Matches($s).Count
  $r.zw = $script:ZeroWidthRe.Matches($s).Count
  return $r
}

# 見えない文字を除く（JSON の文字列の中にしか現れない文字なので、JSON のまま除いても壊れない）
function Remove-HiddenChars([string]$s) {
  $s = $script:TagRe.Replace($s, '')
  $s = $script:VsRunRe.Replace($s, '')
  $s = $script:BidiRe.Replace($s, '')
  return $script:ZeroWidthRe.Replace($s, '')
}

# 警告すべき見えない文字があるか（ゼロ幅の文字だけなら警告しない）
function Test-HiddenCharAlert($r) { return ($r.tag -gt 0 -or $r.vs -gt 0 -or $r.bidi -gt 0) }

function Format-HiddenCharReport($r) {
  $p = [System.Collections.Generic.List[string]]::new()
  if ($r.tag) { $p.Add("Tag 文字 $($r.tag) 個") }
  if ($r.vs) { $p.Add("異体字セレクタの連続 $($r.vs) か所") }
  if ($r.bidi) { $p.Add("双方向制御文字 $($r.bidi) 個") }
  if ($r.zw) { $p.Add("ゼロ幅の文字 $($r.zw) 個") }
  return ($p -join '・')
}

# ---- AI への指示らしい文（日本語・英語） ----
$script:InstructionRe = [regex]::new(
  '(ignore|disregard|forget)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|rules|directions)' +
  '|\byou\s+are\s+now\s+(a|an|in)\b|\bnew\s+instructions?\s*:|\bsystem\s+prompt\b|</?(system|assistant|instructions?)>' +
  '|\b(note|message|instructions?)\s+(to|for)\s+(the\s+)?(ai|llm|assistant|agent|claude|model)\b|\b(ai|llm)\s+(assistants?|agents?|models?)\s*(must|should|need\s+to|are\s+instructed)' +
  '|do\s+not\s+(tell|inform|mention|reveal)\s+(this\s+)?(to\s+)?the\s+user|without\s+(telling|informing|asking)\s+the\s+user' +
  '|\b(developer|debug|god|test)\s+mode\s+(enabled|activated|on)\b|\bjailbreak\b' +
  '|(send|post|upload|exfiltrate|forward|email)\s+[^\n]{0,40}(api[\s_-]?keys?|passwords?|tokens?|secrets?|credentials?|\.env|ssh\s+keys?)' +
  '|(api[\s_-]?keys?|passwords?|tokens?|secrets?|credentials?)\s+[^\n]{0,40}\b(to|via)\s+https?://' +
  '|(run|execute)\s+(the\s+following|this)\s+(command|script|code)' +
  '|(以前|これまで|上記|前|先ほど|今まで)の(指示|命令|ルール|設定)を(すべて|全て)?(無視|忘れ|破棄)|指示を無視して|あなたは(今から|これから)' +
  '|システムプロンプト|(AI|ＡＩ|エージェント|アシスタント|Claude|LLM)(への|に対する|向けの)(指示|命令)|(AI|ＡＩ|エージェント|アシスタント|Claude)(は|が)[^\n。]{0,20}(しなければならない|すること。|してください)' +
  '|(利用者|ユーザー|人間)に(は)?(伝え|知らせ|報告し|言わ|見せ)(ず|ない)' +
  '|(APIキー|API キー|パスワード|トークン|認証情報|秘密鍵|シークレット|\.env)[^\n。]{0,30}(送信|送って|送れ|アップロード|投稿|転送|貼り付け)' +
  '|(次|以下)のコマンドを(実行|すぐに実行)|(開発者|デバッグ|テスト|管理者)モード(を|に|が)?(有効|切り替|オン|入)',
  [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

function Get-Snippet([string]$s, [int]$index, [int]$len) {
  $start = [Math]::Max(0, $index - 10)
  $t = $s.Substring($start, [Math]::Min($s.Length - $start, $len + 30))
  $t = [regex]::Replace($t, '\s+', ' ').Trim()
  if ($t.Length -gt 90) { $t = $t.Substring(0, 90) + '…' }
  return $t
}

# 指示らしい文の最初の1つを返す（なければ $null）
function Find-Instruction([string]$s) {
  if (-not $s) { return $null }
  $m = $script:InstructionRe.Match($s)
  if (-not $m.Success) { return $null }
  return (Get-Snippet $s $m.Index $m.Length)
}

# ---- 見えない HTML の中の指示 ----
# 非表示（display:none・visibility:hidden・font-size:0・opacity:0・白や透明の文字・画面外）の要素、HTML コメント、
# alt・aria-label・title 属性の中に、指示らしい文があるものを探す。非表示の要素自体はよくあるので、指示らしい文があるものだけ
$script:HiddenStyleRe = [regex]::new('<(\w+)\b[^>]*\bstyle\s*=\s*(["''])(?:(?!\2).)*?(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:\.0+)?(?:px|pt|em|rem|%)?\s*[;"'']|opacity\s*:\s*0(?:\.0+)?\s*[;"'']|color\s*:\s*(?:#fff\b|#ffffff\b|white\b|transparent\b|rgba?\(\s*255\s*,\s*255\s*,\s*255)|(?:left|top|text-indent)\s*:\s*-\d{4,})(?:(?!\2).)*\2[^>]*>([\s\S]{10,2000}?)</\1>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$script:HiddenAttrRe = [regex]::new('<\w+\b[^>]*\b(hidden|aria-hidden\s*=\s*["'']true)\b[^>]*>([\s\S]{10,2000}?)<', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$script:CommentRe = [regex]::new('<!--([\s\S]{10,4000}?)-->')
$script:AttrTextRe = [regex]::new('\b(alt|aria-label|title|data-[\w-]+)\s*=\s*(["''])([^"''<>]{20,2000})\2', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

function Find-HiddenHtmlInstructions([string]$s) {
  $found = [System.Collections.Generic.List[string]]::new()
  if (-not $s -or $s.IndexOf('<') -lt 0) { return $found }
  foreach ($m in $script:HiddenStyleRe.Matches($s)) {
    $t = [regex]::Replace($m.Groups[4].Value, '<[^>]+>', ' ')
    $i = Find-Instruction $t
    $how = $m.Groups[3].Value.Trim([char[]]' ;"''')
    if ($i) { $found.Add("非表示の要素（$how）の中の指示：「$i」"); if ($found.Count -ge 5) { return $found } }
  }
  foreach ($m in $script:HiddenAttrRe.Matches($s)) {
    $i = Find-Instruction $m.Groups[2].Value
    if ($i) { $found.Add("非表示の要素の中の指示：「$i」"); if ($found.Count -ge 5) { return $found } }
  }
  foreach ($m in $script:CommentRe.Matches($s)) {
    $i = Find-Instruction $m.Groups[1].Value
    if ($i) { $found.Add("HTML コメントの中の指示：「$i」"); if ($found.Count -ge 5) { return $found } }
  }
  foreach ($m in $script:AttrTextRe.Matches($s)) {
    $i = Find-Instruction $m.Groups[3].Value
    if ($i) { $found.Add("$($m.Groups[1].Value) 属性の中の指示：「$i」"); if ($found.Count -ge 5) { return $found } }
  }
  return $found
}

# ---- JSON の最上位の項目の値を、元の文字列のまま取り出す ----
$script:JsonStringRe = [regex]::new('\G"(?:[^"\\]|\\.)*"')
$script:JsonTokenChars = [char[]]@('"', '{', '}', '[', ']')

function Skip-JsonValue([string]$s, [int]$i) {
  while ($i -lt $s.Length -and [char]::IsWhiteSpace($s[$i])) { $i++ }
  if ($i -ge $s.Length) { return $s.Length }
  $c = $s[$i]
  if ($c -eq '"') { $m = $script:JsonStringRe.Match($s, $i); if ($m.Success) { return $i + $m.Length } else { return $s.Length } }
  if ($c -eq '{' -or $c -eq '[') {
    $depth = 0
    while ($i -lt $s.Length) {
      $j = $s.IndexOfAny($script:JsonTokenChars, $i)
      if ($j -lt 0) { return $s.Length }
      $c = $s[$j]
      if ($c -eq '"') { $m = $script:JsonStringRe.Match($s, $j); if (-not $m.Success) { return $s.Length }; $i = $j + $m.Length; continue }
      if ($c -eq '{' -or $c -eq '[') { $depth++ } else { $depth--; if ($depth -eq 0) { return $j + 1 } }
      $i = $j + 1
    }
    return $s.Length
  }
  $m = [regex]::Match($s.Substring($i, [Math]::Min(64, $s.Length - $i)), '^[^,}\]\s]*')
  return $i + $m.Length
}

# 最上位の項目 $key の値の位置を返す（@{ start; end }。なければ $null）
function Get-JsonTopValueSpan([string]$json, [string]$key) {
  $i = $json.IndexOf('{')
  if ($i -lt 0) { return $null }
  $i++
  while ($i -lt $json.Length) {
    while ($i -lt $json.Length -and ([char]::IsWhiteSpace($json[$i]) -or $json[$i] -eq ',')) { $i++ }
    if ($i -ge $json.Length -or $json[$i] -ne '"') { return $null }
    $m = $script:JsonStringRe.Match($json, $i)
    if (-not $m.Success) { return $null }
    $name = $m.Value.Substring(1, $m.Value.Length - 2)
    $i += $m.Length
    while ($i -lt $json.Length -and ([char]::IsWhiteSpace($json[$i]) -or $json[$i] -eq ':')) { $i++ }
    $end = Skip-JsonValue $json $i
    if ($name -eq $key) { return @{ start = $i; end = $end } }
    $i = $end
  }
  return $null
}

# ---- 文書（Word・Excel・PowerPoint・PDF）の隠し要素 ----
$script:DocExts = @('.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.pptm', '.pdf')

function Open-ZipArchive([string]$path) {
  [void][Reflection.Assembly]::Load('System.IO.Compression, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
  $fs = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  return [IO.Compression.ZipArchive]::new($fs, [IO.Compression.ZipArchiveMode]::Read)
}

function Read-ZipEntryText($zip, [string]$name) {
  $e = $zip.GetEntry($name)
  if (-not $e -or $e.Length -gt 30MB) { return $null }
  $r = [IO.StreamReader]::new($e.Open(), $script:Utf8)
  try { return $r.ReadToEnd() } finally { $r.Dispose() }
}

function Get-XmlText([string]$xml, [string]$tag) {
  $sb = [System.Text.StringBuilder]::new()
  foreach ($m in [regex]::Matches($xml, "<$tag(?:\s[^>]*)?>([^<]*)</$tag>")) { [void]$sb.Append([Net.WebUtility]::HtmlDecode($m.Groups[1].Value)) }
  return $sb.ToString()
}

function Add-TextFinding($list, [string]$label, [string]$text, [int]$minLen) {
  $t = [regex]::Replace($text, '\s+', ' ').Trim()
  if ($t.Length -lt $minLen) { return }
  $i = Find-Instruction $t
  $show = if ($t.Length -gt 60) { $t.Substring(0, 60) + '…' } else { $t }
  if ($i) { $list.Add("$label に指示らしい文：「$i」") } else { $list.Add("$label（$($t.Length) 文字）：「$show」") }
}

# 共通：本文・メタデータ・コメントの見えない文字と指示らしい文
function Add-PartChecks($list, [string]$label, [string]$text) {
  if (-not $text) { return }
  $h = Get-HiddenCharReport $text
  if (Test-HiddenCharAlert $h) {
    $msg = "$label に見えない文字（$(Format-HiddenCharReport $h)）"
    if ($h.tagText) { $msg += "。隠れていた文：「$($h.tagText)」" }
    $list.Add($msg)
  }
}

function Get-DocxFindings($zip) {
  $f = [System.Collections.Generic.List[string]]::new()
  $parts = @($zip.Entries | Where-Object { $_.FullName -match '^word/(document|header\d*|footer\d*|footnotes|endnotes)\.xml$' } | ForEach-Object { $_.FullName })
  $vanish = [System.Text.StringBuilder]::new(); $white = [System.Text.StringBuilder]::new(); $tiny = [System.Text.StringBuilder]::new()
  foreach ($p in $parts) {
    $xml = Read-ZipEntryText $zip $p
    if (-not $xml) { continue }
    Add-PartChecks $f "本文（$p）" (Get-XmlText $xml 'w:t')
    foreach ($m in [regex]::Matches($xml, '<w:r\b[^>]*>([\s\S]*?)</w:r>')) {
      $run = $m.Groups[1].Value
      $rpr = [regex]::Match($run, '<w:rPr>([\s\S]*?)</w:rPr>').Groups[1].Value
      if (-not $rpr) { continue }
      $txt = Get-XmlText $run 'w:t'
      if (-not $txt) { continue }
      if ([regex]::IsMatch($rpr, '<w:vanish(?:\s+w:val="(?:true|1|on)")?\s*/>')) { [void]$vanish.Append($txt) }
      elseif ([regex]::IsMatch($rpr, '<w:color\s+w:val="(?:FFFFFF|FFFFFE|FEFEFE)"', 'IgnoreCase') -and -not [regex]::IsMatch($rpr, '<w:(shd|highlight)\b')) { [void]$white.Append($txt) }
      $sz = [regex]::Match($rpr, '<w:sz\s+w:val="(\d+)"')
      if ($sz.Success -and [int]$sz.Groups[1].Value -lt 8) { [void]$tiny.Append($txt) }
    }
  }
  Add-TextFinding $f '非表示の文字（隠し文字の書式）' $vanish.ToString() 10
  Add-TextFinding $f '白い文字（背景が濃い場合は正常）' $white.ToString() 40
  Add-TextFinding $f '4pt 未満の極小の文字' $tiny.ToString() 10
  $c = Read-ZipEntryText $zip 'word/comments.xml'
  if ($c) {
    $n = [regex]::Matches($c, '<w:comment\b').Count
    $t = Get-XmlText $c 'w:t'
    $i = Find-Instruction $t
    if ($i) { $f.Add("コメント（$n 件）に指示らしい文：「$i」") } elseif ($n -gt 0) { $f.Add("コメントが $n 件あります（本文には表示されません）") }
    Add-PartChecks $f 'コメント' $t
  }
  return $f
}

function Get-XlsxFindings($zip) {
  $f = [System.Collections.Generic.List[string]]::new()
  $wb = Read-ZipEntryText $zip 'xl/workbook.xml'
  if ($wb) {
    foreach ($m in [regex]::Matches($wb, '<sheet\b[^>]*\bname="([^"]*)"[^>]*\bstate="(hidden|veryHidden)"|<sheet\b[^>]*\bstate="(hidden|veryHidden)"[^>]*\bname="([^"]*)"')) {
      $name = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[4].Value }
      $state = if ($m.Groups[2].Success) { $m.Groups[2].Value } else { $m.Groups[3].Value }
      $f.Add("$(if ($state -eq 'veryHidden') { '通常の操作では再表示できない非表示シート' } else { '非表示のシート' })：「$([Net.WebUtility]::HtmlDecode($name))」")
    }
  }
  $ssXml = Read-ZipEntryText $zip 'xl/sharedStrings.xml'
  $shared = [System.Collections.Generic.List[string]]::new()
  if ($ssXml) {
    foreach ($m in [regex]::Matches($ssXml, '<si>([\s\S]*?)</si>')) { $shared.Add((Get-XmlText $m.Groups[1].Value 't')) }
    Add-PartChecks $f '文字列' ($shared -join "`n")
  }
  # 白い文字（塗りつぶしなし）・4pt 未満の文字の書式番号
  $flag = @{}
  $st = Read-ZipEntryText $zip 'xl/styles.xml'
  if ($st) {
    $fonts = [regex]::Matches([regex]::Match($st, '<fonts\b[\s\S]*?</fonts>').Value, '<font\b[^>]*?(?:/>|>([\s\S]*?)</font>)')
    $fills = [regex]::Matches([regex]::Match($st, '<fills\b[\s\S]*?</fills>').Value, '<fill\b[^>]*?(?:/>|>([\s\S]*?)</fill>)')
    $xfs = [regex]::Matches([regex]::Match($st, '<cellXfs\b[\s\S]*?</cellXfs>').Value, '<xf\b[^>]*>')
    for ($k = 0; $k -lt $xfs.Count; $k++) {
      $fid = [regex]::Match($xfs[$k].Value, 'fontId="(\d+)"'); $flid = [regex]::Match($xfs[$k].Value, 'fillId="(\d+)"')
      if (-not $fid.Success -or [int]$fid.Groups[1].Value -ge $fonts.Count) { continue }
      $font = $fonts[[int]$fid.Groups[1].Value].Groups[1].Value
      $fill = if ($flid.Success -and [int]$flid.Groups[1].Value -lt $fills.Count) { $fills[[int]$flid.Groups[1].Value].Groups[1].Value } else { '' }
      $solid = [regex]::IsMatch($fill, 'patternType="solid"') -and -not [regex]::IsMatch($fill, 'fgColor\s+rgb="FFFFFFFF"')
      if ([regex]::IsMatch($font, '<color\s+rgb="FFFFFFFF"', 'IgnoreCase') -and -not $solid) { $flag[$k] = '白い文字（塗りつぶしなし）' }
      $sz = [regex]::Match($font, '<sz\s+val="([\d.]+)"')
      if ($sz.Success -and [double]$sz.Groups[1].Value -lt 4) { $flag[$k] = '4pt 未満の極小の文字' }
    }
  }
  $hiddenRows = 0; $hiddenCols = 0
  $styled = @{}
  foreach ($e in $zip.Entries) {
    if ($e.FullName -notmatch '^xl/worksheets/sheet\d+\.xml$') { continue }
    $xml = Read-ZipEntryText $zip $e.FullName
    if (-not $xml) { continue }
    foreach ($m in [regex]::Matches($xml, '<row\b[^>]*\bhidden="(?:1|true)"[^>]*>([\s\S]*?)</row>')) { if ($m.Groups[1].Value -match '<v>|<is>') { $hiddenRows++ } }
    $hiddenCols += [regex]::Matches($xml, '<col\b[^>]*\bhidden="(?:1|true)"').Count
    if ($flag.Count -gt 0) {
      foreach ($m in [regex]::Matches($xml, '<c\b([^>]*)>([\s\S]*?)</c>')) {
        $s = [regex]::Match($m.Groups[1].Value, '\bs="(\d+)"')
        if (-not $s.Success -or -not $flag.ContainsKey([int]$s.Groups[1].Value)) { continue }
        $label = $flag[[int]$s.Groups[1].Value]
        $v = [regex]::Match($m.Groups[2].Value, '<v>([^<]*)</v>').Groups[1].Value
        $txt = if ($m.Groups[1].Value -match '\bt="s"' -and $v -match '^\d+$' -and [int]$v -lt $shared.Count) { $shared[[int]$v] } else { (Get-XmlText $m.Groups[2].Value 't') + $v }
        if (-not $styled.ContainsKey($label)) { $styled[$label] = [System.Text.StringBuilder]::new() }
        [void]$styled[$label].Append($txt + ' ')
      }
    }
  }
  foreach ($k in $styled.Keys) { Add-TextFinding $f $k $styled[$k].ToString() 20 }
  if ($hiddenRows -gt 0) { $f.Add("値の入った非表示の行が $hiddenRows 行あります") }
  if ($hiddenCols -gt 0) { $f.Add("非表示の列の指定が $hiddenCols か所あります") }
  $cm = [System.Text.StringBuilder]::new(); $n = 0
  foreach ($e in $zip.Entries) {
    if ($e.FullName -notmatch '^xl/(comments\d*|threadedComments/threadedComment\d*)\.xml$') { continue }
    $x = Read-ZipEntryText $zip $e.FullName
    $n += [regex]::Matches($x, '<(comment|threadedComment)\b').Count
    [void]$cm.Append((Get-XmlText $x 't')); [void]$cm.Append((Get-XmlText $x 'text'))
  }
  if ($n -gt 0) {
    $i = Find-Instruction $cm.ToString()
    if ($i) { $f.Add("コメント（$n 件）に指示らしい文：「$i」") }
    Add-PartChecks $f 'コメント' $cm.ToString()
  }
  return $f
}

function Get-PptxFindings($zip) {
  $f = [System.Collections.Generic.List[string]]::new()
  $hidden = 0; $tiny = [System.Text.StringBuilder]::new(); $notes = [System.Text.StringBuilder]::new(); $all = [System.Text.StringBuilder]::new()
  foreach ($e in $zip.Entries) {
    if ($e.FullName -match '^ppt/slides/slide\d+\.xml$') {
      $xml = Read-ZipEntryText $zip $e.FullName
      if (-not $xml) { continue }
      if ([regex]::IsMatch($xml, '<p:sld\b[^>]*\bshow="(?:0|false)"')) { $hidden++ }
      [void]$all.Append((Get-XmlText $xml 'a:t'))
      foreach ($m in [regex]::Matches($xml, '<a:r>([\s\S]*?)</a:r>')) {
        $sz = [regex]::Match($m.Groups[1].Value, '<a:rPr\b[^>]*\bsz="(\d+)"')
        if ($sz.Success -and [int]$sz.Groups[1].Value -lt 400) { [void]$tiny.Append((Get-XmlText $m.Groups[1].Value 'a:t')) }
      }
    } elseif ($e.FullName -match '^ppt/notesSlides/notesSlide\d+\.xml$') {
      [void]$notes.Append((Get-XmlText (Read-ZipEntryText $zip $e.FullName) 'a:t'))
    }
  }
  if ($hidden -gt 0) { $f.Add("非表示のスライドが $hidden 枚あります") }
  Add-PartChecks $f 'スライドの文字' $all.ToString()
  Add-TextFinding $f '4pt 未満の極小の文字' $tiny.ToString() 10
  $i = Find-Instruction $notes.ToString()
  if ($i) { $f.Add("ノート（発表者用のメモ）に指示らしい文：「$i」") }
  Add-PartChecks $f 'ノート' $notes.ToString()
  return $f
}

function Get-PdfFindings([string]$path) {
  $f = [System.Collections.Generic.List[string]]::new()
  $bytes = [IO.File]::ReadAllBytes($path)
  $latin = [Text.Encoding]::GetEncoding(28591)
  $s = $latin.GetString($bytes)
  $invisible = 0; $white = 0
  $lit = [System.Text.StringBuilder]::new()
  $deadline = [DateTime]::Now.AddSeconds(4)
  foreach ($m in [regex]::Matches($s, 'stream\r?\n')) {
    if ([DateTime]::Now -gt $deadline) { $f.Add('（PDF が大きいため途中まで調べました）'); break }
    $start = $m.Index + $m.Length
    $end = $s.IndexOf('endstream', $start)
    if ($end -lt 0) { break }
    $dict = $s.Substring([Math]::Max(0, $m.Index - 400), [Math]::Min(400, $m.Index))
    $dict = $dict.Substring($dict.LastIndexOf('<<') + 1)
    if ($dict -match '/(DCTDecode|JPXDecode|CCITTFaxDecode|JBIG2Decode)' -or $dict -match '/Subtype\s*/Image') { continue }
    $content = $null
    if ($dict -match '/FlateDecode') {
      try {
        $ms = [IO.MemoryStream]::new($bytes, $start + 2, [Math]::Max(0, $end - $start - 2))
        $ds = [IO.Compression.DeflateStream]::new($ms, [IO.Compression.CompressionMode]::Decompress)
        $out = [IO.MemoryStream]::new()
        $buf = [byte[]]::new(65536)
        while (($n = $ds.Read($buf, 0, $buf.Length)) -gt 0) { $out.Write($buf, 0, $n); if ($out.Length -gt 20MB) { break } }
        $content = $latin.GetString($out.ToArray())
      } catch { $content = $null }
    } elseif ($dict -notmatch '/Filter') {
      $content = $s.Substring($start, $end - $start)
    }
    if (-not $content -or $content.IndexOf('BT') -lt 0) { continue }
    foreach ($bt in [regex]::Matches($content, '\bBT\b([\s\S]*?)\bET\b')) {
      $b = $bt.Groups[1].Value
      if ($b -notmatch 'T[jJ\x27\x22]') { continue }
      if ($b -match '(?<![\d.])3\s+Tr\b') { $invisible++ }
      if ($b -match '(?<![\d.])(1(?:\.0+)?\s+1(?:\.0+)?\s+1(?:\.0+)?\s+rg|1(?:\.0+)?\s+g|0\s+0\s+0\s+0\s+k)\s') { $white++ }
      foreach ($t in [regex]::Matches($b, '\(((?:[^()\\]|\\.)*)\)')) { [void]$lit.Append($t.Groups[1].Value); [void]$lit.Append(' ') }
      if ($lit.Length -gt 2MB) { break }
    }
  }
  if ($invisible -gt 0) { $f.Add("見えない描画モード（3 Tr）の文字が $invisible か所あります（スキャン PDF の文字認識の層なら正常）") }
  if ($white -gt 0) { $f.Add("白で描かれた文字が $white か所あります（背景が濃い場合は正常）") }
  $i = Find-Instruction ($lit.ToString() -replace '\\(\d{3}|.)', '')
  if ($i) { $f.Add("文字に指示らしい文：「$i」") }
  foreach ($m in [regex]::Matches($s, '/(Subject|Keywords|Title|Author|Creator)\s*\(((?:[^()\\]|\\.){10,2000})\)')) {
    $i = Find-Instruction $m.Groups[2].Value
    if ($i) { $f.Add("文書のプロパティ（$($m.Groups[1].Value)）に指示らしい文：「$i」") }
  }
  if ($s -match '/JavaScript|/JS\s*[(<]|/Launch\b|/EmbeddedFile') { $f.Add('スクリプト・外部起動・埋め込みファイルの指定があります') }
  return $f
}

# 文書の隠し要素を調べる（見つかったものの一覧）
function Get-DocumentFindings([string]$path) {
  $ext = [IO.Path]::GetExtension($path).ToLowerInvariant()
  $f = [System.Collections.Generic.List[string]]::new()
  if ($ext -eq '.pdf') { return (Get-PdfFindings $path) }
  $zip = Open-ZipArchive $path
  try {
    # 関数の戻り値のリストは配列に展開されるので、詰め直す
    $part = if ($ext -like '.doc*') { Get-DocxFindings $zip } elseif ($ext -like '.xls*') { Get-XlsxFindings $zip } elseif ($ext -like '.ppt*') { Get-PptxFindings $zip } else { @() }
    foreach ($x in @($part)) { if ($x) { $f.Add($x) } }
    foreach ($p in @('docProps/core.xml', 'docProps/app.xml', 'docProps/custom.xml')) {
      $x = Read-ZipEntryText $zip $p
      if (-not $x) { continue }
      $t = [regex]::Replace($x, '<[^>]+>', ' ')
      $i = Find-Instruction ([Net.WebUtility]::HtmlDecode($t))
      if ($i) { $f.Add("文書のプロパティ（$p）に指示らしい文：「$i」") }
      Add-PartChecks $f "文書のプロパティ（$p）" $t
    }
    if ($zip.Entries | Where-Object { $_.FullName -match 'vbaProject\.bin$' }) { $f.Add('マクロ（VBA）が含まれています') }
  } finally { $zip.Dispose() }
  return $f
}

# テキストのファイル（HTML・Markdown 等）を調べる
function Get-TextFindings([string]$text) {
  $f = [System.Collections.Generic.List[string]]::new()
  $h = Get-HiddenCharReport $text
  if (Test-HiddenCharAlert $h) {
    $msg = "見えない文字（$(Format-HiddenCharReport $h)）"
    if ($h.tagText) { $msg += "。隠れていた文：「$($h.tagText)」" }
    $f.Add($msg)
  }
  foreach ($x in (Find-HiddenHtmlInstructions $text)) { $f.Add($x) }
  return $f
}
