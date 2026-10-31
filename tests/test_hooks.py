# security-self-check のフックのテスト（py -3 tests/test_hooks.py）
# 段階1（試行）・段階2（本番）・個別の上書きで、各フックの「止める・確認・注意・何もしない」を確かめる
import json
import os
import shutil
import subprocess
import sys
import time

sys.stdout.reconfigure(encoding="utf-8")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "plugins", "security-self-check", "scripts")
WORK = os.path.join(ROOT, "tests", "_work")
B = "\\"

def _force(func, path, _):
    os.chmod(path, 0o666)  # git の内部ファイルなど読み取り専用のものも消す
    func(path)


if os.path.exists(WORK):
    shutil.rmtree(WORK, onerror=_force)
os.makedirs(WORK)


def run(script, data=None, env=None, args=()):
    e = {k: v for k, v in os.environ.items() if not k.startswith("KUSAKABE_GUARD_")}
    e["LOCALAPPDATA"] = os.path.join(WORK, "localappdata")
    e.update(env or {})
    t = time.time()
    r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", os.path.join(SCRIPTS, script), *args],
                       input=json.dumps(data, ensure_ascii=False).encode("utf-8") if data is not None else b"", capture_output=True, env=e)
    out = r.stdout.decode("utf-8", "replace").strip()
    return r.returncode, out, time.time() - t


def kind(out):
    """出力から結果の種類を判定する：none / warn / ask / deny / block"""
    if not out:
        return "none"
    o = json.loads(out)
    h = o.get("hookSpecificOutput", {})
    if o.get("decision") == "block":
        return "block"
    if h.get("permissionDecision") == "deny":
        return "deny"
    if h.get("permissionDecision") == "ask":
        return "ask"
    if o.get("systemMessage"):
        return "warn"
    return "other"


S1 = {}
S2 = {"KUSAKABE_GUARD_STAGE": "2"}
P = lambda s: {"hook_event_name": "UserPromptSubmit", "prompt": s}
T = lambda tool, inp: {"session_id": "t", "cwd": f"C:{B}proj", "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": inp}

CASES = [
    # ---- H1 プロンプト送信前 ----
    ("H1 段階1：マイナンバーは注意", "prompt-guard.ps1", P("番号は 1234 5678 9018 です"), S1, "warn"),
    ("H1 段階2：マイナンバーは止める", "prompt-guard.ps1", P("番号は 1234 5678 9018 です"), S2, "block"),
    ("H1 検査用数字が合わない12桁は通す", "prompt-guard.ps1", P("番号は 1234 5678 9012 です"), S2, "none"),
    ("H1 URL の中の数字は通す", "prompt-guard.ps1", P("エラーが出ます https://app-sample-123456789018.asia-northeast1.run.app/v/0000"), S2, "none"),
    ("H1 日時の数字は通す", "prompt-guard.ps1", P("ログの時刻 202610241030 を確認"), S2, "none"),
    ("H1 正しいカード番号は止める", "prompt-guard.ps1", P("カード 4111-1111-1111-1111 で決済"), S2, "block"),
    ("H1 Luhn が合わない16桁は通す", "prompt-guard.ps1", P("注文番号 1234-5678-9012-3456"), S2, "none"),
    ("H1 社外秘の表示は止める", "prompt-guard.ps1", P("顧客の社外秘資料を参照して"), S2, "block"),
    ("H1 社内アドレスの列挙は通す", "prompt-guard.ps1", P("管理者に a@kusakabe.com、b@kusakabe.com、c@mail.kusakabe.com を追加"), S2, "none"),
    ("H1 社外の連絡先3件は止める", "prompt-guard.ps1", P("顧客 c@example.co.jp、d@example.jp、090-1111-2222 に連絡"), S2, "block"),
    ("H1 同じ連絡先の繰り返しは通す", "prompt-guard.ps1", P("c@example.co.jp に見積、C@Example.co.jp に請求、090-1111-2222 / 09011112222"), S2, "none"),
    ("H1 社内を装ったドメインは社外", "prompt-guard.ps1", P("x@kusakabe.com.evil.jp、y@evil.jp、z@evil.jp"), S2, "block"),
    ("H1 #確認済 は通す", "prompt-guard.ps1", P("#確認済 番号は 1234 5678 9018"), S2, "none"),
    ("H1 off は何もしない", "prompt-guard.ps1", P("番号は 1234 5678 9018"), {"KUSAKABE_GUARD_STAGE": "2", "KUSAKABE_GUARD_H1": "off"}, "none"),
    ("H1 通常の依頼は通す", "prompt-guard.ps1", P("工番 2810 の仕様書を確認して"), S2, "none"),
    # ---- H2 認証情報・社外秘フォルダ ----
    ("H2 段階2：社外秘フォルダの読み取りは止める", "pretool-guard.ps1", T("Read", {"file_path": f"C:{B}共有{B}社外秘{B}見積.xlsx"}), S2, "deny"),
    ("H2 段階1：社外秘フォルダは注意", "pretool-guard.ps1", T("Read", {"file_path": f"C:{B}共有{B}社外秘{B}見積.xlsx"}), S1, "warn"),
    ("H2 SSH 鍵を cat は止める", "pretool-guard.ps1", T("Bash", {"command": "cat ~/.ssh/id_rsa"}), S2, "deny"),
    ("H2 clasp のトークン（PowerShell）は止める", "pretool-guard.ps1", T("PowerShell", {"command": f"Get-Content C:{B}Users{B}a{B}.clasprc.json"}), S2, "deny"),
    ("H2 スクリプト経由の .env は止める", "pretool-guard.ps1", T("Bash", {"command": "py -3 -c \"open('.env').read()\""}), S2, "deny"),
    ("H2 gcloud の認証フォルダは止める", "pretool-guard.ps1", T("Grep", {"pattern": "token", "path": f"C:{B}Users{B}a{B}AppData{B}Roaming{B}gcloud"}), S2, "deny"),
    ("H2 コメント中の社外秘は通す", "pretool-guard.ps1", T("Bash", {"command": "cat >> .gitignore <<'EOF'\n# 図面（社外秘）は入れない\nEOF"}), S2, "none"),
    ("H2 書く本文の社外秘は通す", "pretool-guard.ps1", T("Write", {"file_path": f"C:{B}proj{B}README.md", "content": "社外秘の資料は扱わない"}), S2, "none"),
    ("H2 通常のファイルは通す", "pretool-guard.ps1", T("Read", {"file_path": f"C:{B}proj{B}src{B}app.py"}), S2, "none"),
    ("H2 environment.ts は通す", "pretool-guard.ps1", T("Edit", {"file_path": f"C:{B}proj{B}environment.ts", "old_string": "a", "new_string": "b"}), S2, "none"),
    ("H2 gcloud をフルパスで呼ぶのは通す", "pretool-guard.ps1", T("Bash", {"command": "\"/c/Users/a/AppData/Local/Google/Cloud SDK/google-cloud-sdk/bin/gcloud\" config list"}), S2, "none"),
    # ---- H3 外部への送信 ----
    ("H3 段階2：メール送信は確認", "pretool-guard.ps1", T("mcp__m365__outlook_send_mail", {"to": ["c@example.co.jp"], "subject": "見積書の送付", "body": "…"}), S2, "ask"),
    ("H3 段階2：Teams 投稿は確認", "pretool-guard.ps1", T("mcp__m365__teams_send_chat_message", {"chat_id": "x", "message": "…"}), S2, "ask"),
    ("H3 メールの検索は対象外", "pretool-guard.ps1", T("mcp__m365__outlook_email_search", {"query": "見積"}), S2, "none"),
    ("H3 段階1：送信は何もしない", "pretool-guard.ps1", T("mcp__m365__outlook_send_mail", {"to": ["c@example.co.jp"], "subject": "x"}), S1, "none"),
    # ---- H4 デプロイ ----
    ("H4 gcloud run deploy は注意", "pretool-guard.ps1", T("Bash", {"command": "gcloud run deploy app-x --source . --region asia-northeast1"}), S2, "warn"),
    ("H4 bash deploy.sh は注意", "pretool-guard.ps1", T("Bash", {"command": "cd /c/proj && bash deploy.sh"}), S1, "warn"),
    ("H4 受付自身のデプロイスクリプトは対象外", "pretool-guard.ps1", T("Bash", {"command": "bash infra/deploy_gateway.sh"}), S2, "none"),
    ("H4 kdeploy は対象外", "pretool-guard.ps1", T("Bash", {"command": "py -3 kdeploy.py deploy --dir ."}), S2, "none"),
    ("H4 block にすると止める", "pretool-guard.ps1", T("Bash", {"command": "gcloud run deploy app-x --source ."}), {"KUSAKABE_GUARD_H4": "block"}, "deny"),
    # ---- H6 取り返しのつかない操作 ----
    ("H6 段階2：Cloud Run の削除は確認", "pretool-guard.ps1", T("Bash", {"command": "gcloud run services delete app-x --region=asia-northeast1 --quiet"}), S2, "ask"),
    ("H6 段階2：Secret の削除は確認", "pretool-guard.ps1", T("Bash", {"command": "gcloud secrets delete api-key --quiet"}), S2, "ask"),
    ("H6 段階2：強制 push は確認", "pretool-guard.ps1", T("Bash", {"command": "git push --force origin main"}), S2, "ask"),
    ("H6 段階2：reset --hard は確認", "pretool-guard.ps1", T("Bash", {"command": "git reset --hard HEAD~3"}), S2, "ask"),
    ("H6 通常の push は通す", "pretool-guard.ps1", T("Bash", {"command": "git push origin main"}), S2, "none"),
    ("H6 一時フォルダの削除は通す", "pretool-guard.ps1", T("Bash", {"command": "rm -rf _tmp_preview"}), S2, "none"),
    ("H6 段階1：削除は何もしない", "pretool-guard.ps1", T("Bash", {"command": "gcloud run services delete app-x --quiet"}), S1, "none"),
    ("H6 段階1でも個別に ask にできる", "pretool-guard.ps1", T("Bash", {"command": "gcloud run services delete app-x --quiet"}), {"KUSAKABE_GUARD_H6": "ask"}, "ask"),
    # ---- H7 全員への公開 ----
    ("H7 段階2：allUsers の付与は確認", "pretool-guard.ps1", T("Bash", {"command": "gcloud run services add-iam-policy-binding app-x --member=allUsers --role=roles/run.invoker"}), S2, "ask"),
    ("H7 段階2：公開リポジトリの作成は確認", "pretool-guard.ps1", T("Bash", {"command": "gh repo create kusakabe-denki/x --public"}), S2, "ask"),
    ("H7 通常の権限付与は通す", "pretool-guard.ps1", T("Bash", {"command": "gcloud projects add-iam-policy-binding p --member=serviceAccount:a@p.iam.gserviceaccount.com --role=roles/viewer"}), S2, "none"),
    ("H7＋H4 は確認（注意も添える）", "pretool-guard.ps1", T("Bash", {"command": "gcloud run deploy app-x --source . --allow-unauthenticated"}), S2, "ask"),
    # ---- 壊れた入力でも作業を止めない ----
    ("壊れた入力は何もしない（プロンプト）", "prompt-guard.ps1", None, S2, "none"),
    ("壊れた入力は何もしない（ツール）", "pretool-guard.ps1", None, S2, "none"),
]

ng = 0
times = []
for name, script, data, env, expect in CASES:
    code, out, sec = run(script, data, env)
    times.append(sec)
    try:
        got = kind(out)
    except ValueError:
        got = "不正な JSON"
    ok = code == 0 and got == expect
    ng += not ok
    print(f"{'OK' if ok else 'NG'} {name}（{got}）")
    if not ok:
        print("    終了コード", code, "出力", out[:200])

# 確認の理由・止める理由が日本語で返るか（H7＋H4 は注意も添える）
_, out, _ = run("pretool-guard.ps1", T("Bash", {"command": "gcloud run deploy app-x --source . --allow-unauthenticated"}), S2)
o = json.loads(out)
ok = "誰でもアクセス" in o["hookSpecificOutput"]["permissionDecisionReason"] and "デプロイ受付" in o.get("systemMessage", "")
ng += not ok
print(f"{'OK' if ok else 'NG'} 確認の理由と注意が日本語で返る")

# ---- H5 起動時の自己チェック ----
proj = os.path.join(WORK, "proj")
os.makedirs(os.path.join(proj, "src"))
os.makedirs(os.path.join(proj, "node_modules", "x"))
open(os.path.join(proj, ".env"), "w", encoding="utf-8").write("PORT=8080\nAPI_KEY=dummy-value-123\n")
open(os.path.join(proj, ".env.example"), "w", encoding="utf-8").write("API_KEY=xxxx\n")
open(os.path.join(proj, "src", "token.py"), "w", encoding="utf-8").write("import json, os\np = os.path.expanduser('~/.clasprc.json')\ntok = json.load(open(p))\n")
open(os.path.join(proj, "src", "app.js"), "w", encoding="utf-8").write("const k = 'AIza" + "B" * 35 + "';\n")
open(os.path.join(proj, "sa.json"), "w", encoding="utf-8").write('{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\\nX\\n-----END PRIVATE KEY-----\\n"}')
open(os.path.join(proj, "node_modules", "x", "k.js"), "w", encoding="utf-8").write("const k = 'AIza" + "C" * 35 + "';\n")
data_dir = os.path.join(WORK, "plugindata")
env5 = {"CLAUDE_PROJECT_DIR": proj}
ss = {"hook_event_name": "SessionStart", "source": "startup", "cwd": proj}

code, out, sec = run("session-check.ps1", ss, env5, ("-DataDir", data_dir))
times.append(sec)
o = json.loads(out) if out else {}
ctx = o.get("hookSpecificOutput", {}).get("additionalContext", "")
ok = "4 件" in o.get("systemMessage", "") and "dummy-value-123" not in out and "node_modules" not in ctx
ng += not ok
print(f"{'OK' if ok else 'NG'} H5 起動時に4件を知らせ、値や node_modules は出さない（{o.get('systemMessage', '')[:60]}）")

code, out, _ = run("session-check.ps1", ss, env5, ("-DataDir", data_dir))
ok = out == ""
ng += not ok
print(f"{'OK' if ok else 'NG'} H5 同じ日の2回目は何もしない")

code, out, _ = run("session-check.ps1", {**ss, "source": "compact"}, {"CLAUDE_PROJECT_DIR": os.path.join(WORK, "other")}, ("-DataDir", data_dir))
ok = out == ""
ng += not ok
print(f"{'OK' if ok else 'NG'} H5 compact では動かない")

code, out, _ = run("session-check.ps1", None, None, ("-Full", "-ProjectDir", proj))
ok = "要修正の箇所：4 件" in out and ".env に秘密情報" in out and "clasp のトークン" in out and "Google の API キー（直書き）" in out and "サービスアカウントの鍵ファイル" in out and "dummy-value-123" not in out
ng += not ok
print(f"{'OK' if ok else 'NG'} H5 スキルからの全件一覧（4件・種類・値を出さない）")

clean = os.path.join(WORK, "clean"); os.makedirs(clean)
open(os.path.join(clean, "app.py"), "w", encoding="utf-8").write("print('hello')\n")
code, out, _ = run("session-check.ps1", {**ss, "cwd": clean}, {"CLAUDE_PROJECT_DIR": clean}, ("-DataDir", data_dir))
ok = out == ""
ng += not ok
print(f"{'OK' if ok else 'NG'} H5 問題のないプロジェクトは何も出さない")

code, out, _ = run("session-check.ps1", {**ss, "cwd": os.environ["USERPROFILE"]}, {"CLAUDE_PROJECT_DIR": os.environ["USERPROFILE"]}, ("-DataDir", data_dir))
ok = out == ""
ng += not ok
print(f"{'OK' if ok else 'NG'} H5 ホームフォルダでは調べない")

# ---- H8 設定変更の記録 ----
code, out, _ = run("config-log.ps1", {"hook_event_name": "ConfigChange", "source": "project_settings", "file_path": f"C:{B}proj{B}.claude{B}settings.json"})
log = os.path.join(WORK, "localappdata", "ClaudeGuard", "config-change.log")
ok = code == 0 and os.path.exists(log) and "project_settings" in open(log, encoding="utf-8").read()
ng += not ok
print(f"{'OK' if ok else 'NG'} H8 設定の変更を記録する")

# ---- ログ ----
tlog = os.path.join(WORK, "localappdata", "ClaudeGuard", "tool-guard.log")
ok = os.path.exists(tlog) and "H2-block" in open(tlog, encoding="utf-8").read()
ng += not ok
print(f"{'OK' if ok else 'NG'} 止めた記録が残る")

total = len(CASES) + 9
print(f"\n処理時間：平均 {sum(times) / len(times):.2f} 秒、最大 {max(times):.2f} 秒")
print(f"結果：{total - ng}/{total} 件 OK")
sys.exit(1 if ng else 0)
