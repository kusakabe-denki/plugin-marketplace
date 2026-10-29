# security-self-check のアイコン（A：盾とチェック）を 512×512 の PNG で作る
# 実行：powershell -ExecutionPolicy Bypass -File tools\make_icon.ps1
Add-Type -AssemblyName System.Drawing
$out = [IO.Path]::Combine($PSScriptRoot, '..', 'plugins', 'security-self-check', '.claude-plugin', 'icon.png')
$s = 512 / 120.0
$bmp = New-Object System.Drawing.Bitmap 512, 512
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = 'AntiAlias'
$g.Clear([System.Drawing.Color]::Transparent)
$blue = [System.Drawing.Color]::FromArgb(255, 0x18, 0x5F, 0xA5)

# 角の丸い四角
$r = 24 * $s; $x = 4 * $s; $w = 112 * $s
$bg = New-Object System.Drawing.Drawing2D.GraphicsPath
$bg.AddArc($x, $x, $r * 2, $r * 2, 180, 90); $bg.AddArc($x + $w - $r * 2, $x, $r * 2, $r * 2, 270, 90)
$bg.AddArc($x + $w - $r * 2, $x + $w - $r * 2, $r * 2, $r * 2, 0, 90); $bg.AddArc($x, $x + $w - $r * 2, $r * 2, $r * 2, 90, 90); $bg.CloseFigure()
$g.FillPath((New-Object System.Drawing.SolidBrush $blue), $bg)

# 盾
$sh = New-Object System.Drawing.Drawing2D.GraphicsPath
$sh.AddLine(60 * $s, 22 * $s, 90 * $s, 34 * $s); $sh.AddLine(90 * $s, 34 * $s, 90 * $s, 58 * $s)
$sh.AddBezier(90 * $s, 58 * $s, 90 * $s, 78 * $s, 77 * $s, 92 * $s, 60 * $s, 99 * $s)
$sh.AddBezier(60 * $s, 99 * $s, 43 * $s, 92 * $s, 30 * $s, 78 * $s, 30 * $s, 58 * $s)
$sh.AddLine(30 * $s, 58 * $s, 30 * $s, 34 * $s); $sh.CloseFigure()
$g.FillPath([System.Drawing.Brushes]::White, $sh)

# チェック
$pen = New-Object System.Drawing.Pen $blue, (8 * $s)
$pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
$g.DrawLines($pen, [System.Drawing.PointF[]]@(
  (New-Object System.Drawing.PointF (45 * $s), (60 * $s)),
  (New-Object System.Drawing.PointF (56 * $s), (71 * $s)),
  (New-Object System.Drawing.PointF (77 * $s), (49 * $s))))

$bmp.Save([IO.Path]::GetFullPath($out), [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Output "作成しました：$([IO.Path]::GetFullPath($out))"
