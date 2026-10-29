# H8：Claude Code の設定ファイルが変わったら記録する（ConfigChange・記録のみで止めない）
# 記録先：%LOCALAPPDATA%\ClaudeGuard\config-change.log
# 組織設定（管理画面からの配布）の変更は、仕様上このフックでは検知できない
. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
try {
  if ((Get-GuardMode 'H8') -eq 'off') { exit 0 }
  $raw = Read-HookInput
  $source = Get-JsonString $raw 'source'
  $file = Get-JsonString $raw 'file_path'
  Write-GuardLog 'config-change' $source $file
} catch {}
exit 0
