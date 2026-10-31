# H8：Claude Code の設定ファイルがセッション中に変わったら記録する（ConfigChange）
#   on（段階1）：記録だけ
#   block（段階2）：プロジェクトの設定（.claude/settings.json・settings.local.json）の変更は、実行中のセッションに反映させない。
#                   乗っ取られた Claude や外部のプログラムが、作業中に安全装置を外すのを防ぐ。個人の設定（user_settings）は記録だけ
#                   （ConfigChange は「確認を求める」ができないため）。止めても画面には出ないので、記録で確かめる
# 記録先：%LOCALAPPDATA%\ClaudeGuard\config-change.log
# 組織設定（管理画面からの配布・レジストリ）の変更は、仕様上このフックでは検知できない
. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))
try {
  $mode = Get-GuardMode 'H8'
  if ($mode -eq 'off') { exit 0 }
  $raw = Read-HookInput
  $source = Get-JsonString $raw 'source'
  $file = Get-JsonString $raw 'file_path'
  if ($mode -eq 'block' -and ($source -eq 'project_settings' -or $source -eq 'local_settings')) {
    Write-GuardLog 'config-change' "$source-blocked" $file
    Write-GuardEvent 'H8' 'block' 'ConfigChange' "$source の変更を反映させなかった"
    Write-HookJson ('{"decision":"block","reason":' + (ConvertTo-JsonText '会社のセキュリティルール（H8）：作業中のプロジェクト設定の変更は反映しません。Claude Code を起動し直すと読み込まれます。') + '}')
    exit 0
  }
  Write-GuardLog 'config-change' $source $file
  if ($source -eq 'user_settings') { Write-GuardEvent 'H8' 'log' 'ConfigChange' 'user_settings の変更' }
} catch {}
exit 0
