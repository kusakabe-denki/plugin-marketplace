"""kusakabe-deploy：デプロイ受付への送信（Python 標準ライブラリだけ・Windows）

  py -3 kdeploy.py login                      Microsoft 365 でサインイン（デバイスコード方式。表示されたコードを
                                              https://microsoft.com/devicelogin に入れる。QR コードの画面を通らない）
  py -3 kdeploy.py login --browser [--account …] [--inprivate]   ブラウザを開く方式（認可コード＋PKCE）
  py -3 kdeploy.py whoami                     サインインしている人
  py -3 kdeploy.py init --name app-xxx [--dir .] [--target prod] [--source-dir .]   名前の予約と .kusakabe/app.json の作成
  py -3 kdeploy.py preview [--dir .] [--port 8080]   app.json の preview どおりに手元で起動する（Cloud Run には触れない）
  py -3 kdeploy.py preview --ok [--dir .]     利用者が画面を確かめて OK を出したことを記録する（deploy の前に必要）
  py -3 kdeploy.py preview --stop [--dir .]   手元で起動したアプリを止める
  py -3 kdeploy.py deploy [--dir .] [--no-wait] [--overwrite] [--skip-preview "理由"]   ソースを送ってデプロイを依頼し、結果が出るまで待つ
  py -3 kdeploy.py status <デプロイ ID> [--dir .]   状態の確認
  py -3 kdeploy.py files [--dir .]             送るファイルの一覧だけを表示（送らない）
  py -3 kdeploy.py pull [--dir .] [--name app-xxx]   GitHub の最新の版を取り込む（空のフォルダならそこに展開、
                                              作業中のフォルダなら .kusakabe/incoming/<版>/ に置いて違いを表示）
  py -3 kdeploy.py merged [--dir .] [--yes]    取り込んだ版と自分の変更を合わせ終えたことを記録する
  py -3 kdeploy.py emergency on --reason "…" [--hours 24]   （管理者）緊急モードを始める（GitHub が止まったときだけ）
  py -3 kdeploy.py emergency off|status        （管理者）緊急モードを終える／状態と、まだ GitHub に戻していない版を見る
  py -3 kdeploy.py bcp-replay [--name app-xxx] [--merge]   （管理者）緊急モードで出した版を bcp/日付 ブランチに記録し、PR を作る

緊急モード（2026-11-01）：GitHub が止まっている間、管理者の承認（期限つき）で GitHub への記録を後回しにし、検査 → 反映だけを通す。
ソースは受付が保管し、復旧後に bcp-replay で main に戻す。戻るまでは、そのアプリの通常のデプロイは止まる。

上書き防止（2026-11-01）：前回 GitHub に記録された版を .kusakabe/state.json に残して送り、受付は main の先頭と違えば止める
（ほかの人が先に更新した版を、古い版から作ったソースで消さない）。止められたら pull → 合わせる → merged → deploy。

画面の事前確認（2026-11-02）：Cloud Run への反映は数分かかるので、直すたびに出さず、手元で起動した画面を利用者が確かめてから出す。
preview --ok で、確かめたときのファイルの指紋を .kusakabe/state.json に残し、deploy は今のファイルと指紋が同じときだけ送る
（確かめた後に直したら確かめ直す）。画面のない内部 API（auth: iam）は対象外。画面に関係しない変更だけのときは --skip-preview "理由"。
確かめたか・省略した理由は GitHub の記録（コミットのメッセージ）に残る。PC 側の確認なので、すり抜けを防ぐ仕組みではない。

終了コード：0 成功／2 検査で止めた・確認に失敗／3 ほかの人の更新を先に取り込む必要がある／4 画面の確認が済んでいない／1 そのほかの失敗
更新用のトークンは Windows の DPAPI で暗号化して %LOCALAPPDATA%\\kusakabe-deploy\\token.bin に置く（ほかの PC・ほかの人では読めない）。
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import ctypes.wintypes as wt
import hashlib
import http.server
import io
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

GATEWAY = os.environ.get("KUSAKABE_GATEWAY", "https://deploy-gateway-276054565253.asia-northeast1.run.app")
TENANT = "b825147d-5f85-4b12-bda8-8e3108196121"
CLIENT_ID = "fabe1e6f-4a8a-4f4a-a9b1-6a11d9785d31"
SCOPE = f"api://{CLIENT_ID}/deploy offline_access openid profile"
AUTH = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0"
STORE = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "kusakabe-deploy"
MAX_BYTES = 50 * 1024 * 1024
TERMINAL = {"succeeded", "blocked", "probe_failed", "failed", "error"}
MAX_EXTRACT = 200 * 1024 * 1024   # pull で展開する合計の上限
MAX_FILES = 5000
EXCLUDE = re.compile(
    r"(^|/)(\.git|node_modules|__pycache__|\.venv|venv|\.pytest_cache)(/|$)"
    r"|(^|/)\.env($|\.(?!example$|sample$|template$))"
    r"|\.(pem|key|p12|pfx|keystore|jks|log|pyc)$|(^|/)id_(rsa|ed25519)"
    r"|(^|/)\.claude/(settings\.local\.json|worktrees/)|(^|/)key\.json$|(^|/)\.deploy_setup_done$|(^|/)\.clasprc\.json$"
    r"|^\.kusakabe/(state\.json$|state\.json\.[^/]*\.tmp$|incoming/)", re.I)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


# ------------------------------------------------------------------ DPAPI
class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(data, len(data))
    src, dst = _Blob(len(data), buf), _Blob()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(src), None, None, None, None, 0x01, ctypes.byref(dst))  # CRYPTPROTECT_UI_FORBIDDEN
    if not ok:
        raise OSError("DPAPI で暗号化・復号できません")
    try:
        return ctypes.string_at(dst.pbData, dst.cbData)
    finally:
        kernel32.LocalFree(dst.pbData)


def _save_refresh(token: str) -> None:
    STORE.mkdir(parents=True, exist_ok=True)
    (STORE / "token.bin").write_bytes(_dpapi(token.encode("utf-8"), True))


def _load_refresh() -> str | None:
    p = STORE / "token.bin"
    if not p.exists():
        return None
    try:
        return _dpapi(p.read_bytes(), False).decode("utf-8")
    except OSError:
        return None


# ------------------------------------------------------------------ サインイン（認可コード＋PKCE）
def _post_form(url: str, data: dict) -> dict:
    req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(), method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        raise SystemExit(f"サインインに失敗しました（{e.code}）：{body[:300]}")


def _open_browser(url: str, inprivate: bool) -> None:
    """InPrivate を選んだときは Edge の InPrivate ウィンドウで開く（普段のアカウントで自動サインインさせない）"""
    if inprivate:
        for exe in (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"):
            if Path(exe).exists():
                subprocess.Popen([exe, "-inprivate", url])
                return
        print("Edge が見つからないので、既定のブラウザで開きます")
    webbrowser.open(url)


def login_device() -> str:
    """デバイスコード方式（既定）：表示されたコードを https://microsoft.com/devicelogin に入れてサインインする。
    アプリがブラウザを開かないので、QR コードの認証画面で止まる問題（この PC の環境で発生）を避けられる"""
    dc = _post_form(f"{AUTH}/devicecode", {"client_id": CLIENT_ID, "scope": SCOPE})
    print("\n  1. ブラウザ（スマートフォンでも可）で " + dc["verification_uri"] + " を開く")
    print("  2. コード  " + dc["user_code"] + "  を入れる")
    print("  3. デプロイに使うアカウントでサインインし、承諾する\n")
    deadline = time.time() + int(dc.get("expires_in", 900))
    interval = int(dc.get("interval", 5))
    while time.time() < deadline:
        time.sleep(interval)
        req = urllib.request.Request(f"{AUTH}/token", method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"},
                                     data=urllib.parse.urlencode({"client_id": CLIENT_ID, "device_code": dc["device_code"],
                                                                  "grant_type": "urn:ietf:params:oauth:grant-type:device_code"}).encode())
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                tok = json.loads(r.read())
        except urllib.error.HTTPError as e:
            err = json.loads(e.read() or b"{}")
            code = err.get("error", "")
            if code == "authorization_pending":
                continue
            if code == "slow_down":
                interval += 5
                continue
            if code in ("invalid_client", "unauthorized_client") or "AADSTS7000218" in err.get("error_description", ""):
                raise SystemExit("デバイスコード方式が許可されていません。Entra のアプリ「デプロイ受付」の［認証］→［パブリック クライアント フローを許可する］を「はい」にしてください")
            raise SystemExit(f"サインインできませんでした：{err.get('error_description', code)[:300]}")
        if tok.get("refresh_token"):
            _save_refresh(tok["refresh_token"])
        return tok["access_token"]
    raise SystemExit("時間切れです。もう一度 login してください")


def login(account: str = "", inprivate: bool = False) -> str:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)
    got: dict = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            got.update({k: v[0] for k, v in q.items()})
            ok = "code" in got and got.get("state") == state
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            msg = "サインインしました。この画面を閉じて Claude Code に戻ってください。" if ok else "サインインできませんでした。Claude Code の表示を確認してください。"
            self.wfile.write(f"<!doctype html><meta charset=utf-8><p style='font:16px sans-serif;margin:40px'>{msg}</p>".encode())

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    redirect = f"http://localhost:{srv.server_port}"
    params = {"client_id": CLIENT_ID, "response_type": "code", "redirect_uri": redirect, "response_mode": "query",
              "scope": SCOPE, "code_challenge": challenge, "code_challenge_method": "S256", "state": state,
              "prompt": "select_account"}
    if account:
        params.update(login_hint=account, prompt="login")
    url = f"{AUTH}/authorize?" + urllib.parse.urlencode(params)
    t = threading.Thread(target=srv.handle_request, daemon=True)
    t.start()
    print(f"ブラウザで Microsoft 365 の確認画面を開きます（{account or 'デプロイに使うアカウント'}でサインインしてください）...")
    _open_browser(url, inprivate)
    t.join(timeout=300)
    srv.server_close()
    if got.get("state") != state or "code" not in got:
        raise SystemExit("サインインできませんでした：" + got.get("error_description", "時間切れか、取り消されました")[:300])
    tok = _post_form(f"{AUTH}/token", {"client_id": CLIENT_ID, "grant_type": "authorization_code", "code": got["code"],
                                       "redirect_uri": redirect, "code_verifier": verifier, "scope": SCOPE})
    if tok.get("refresh_token"):
        _save_refresh(tok["refresh_token"])
    return tok["access_token"]


_access: dict = {"token": "", "exp": 0.0}


def access_token() -> str:
    if _access["token"] and _access["exp"] - time.time() > 120:
        return _access["token"]
    rt = _load_refresh()
    tok = None
    if rt:
        req = urllib.request.Request(f"{AUTH}/token", method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"},
                                     data=urllib.parse.urlencode({"client_id": CLIENT_ID, "grant_type": "refresh_token",
                                                                  "refresh_token": rt, "scope": SCOPE}).encode())
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                tok = json.loads(r.read())
        except urllib.error.HTTPError:
            tok = None
    if tok:
        if tok.get("refresh_token"):
            _save_refresh(tok["refresh_token"])
        _access.update(token=tok["access_token"], exp=time.time() + int(tok.get("expires_in", 3600)))
        return _access["token"]
    t = login_device()
    _access.update(token=t, exp=time.time() + 3000)
    return t


# ------------------------------------------------------------------ 受付への問い合わせ
class ApiError(SystemExit):
    """受付のエラー応答。表示は従来どおりで、呼び出し側は code・detail で分けられる"""
    def __init__(self, code: int, detail):
        super().__init__(f"受付がエラーを返しました（{code}）：{json.dumps(detail, ensure_ascii=False)[:1500]}")
        self.code, self.detail = code, detail


def api(method: str, path: str, body: dict | None = None, timeout: int = 60) -> dict:
    req = urllib.request.Request(GATEWAY + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {access_token()}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        txt = e.read().decode("utf-8", "replace")
        try:
            detail = json.loads(txt).get("detail", txt)
        except json.JSONDecodeError:
            detail = txt
        raise ApiError(e.code, detail)


# ------------------------------------------------------------------ 送るファイル
def list_files(root: Path) -> list[str]:
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-co", "--exclude-standard", "-z"],
                             capture_output=True, check=True).stdout.decode("utf-8")
        names = [n for n in out.split("\0") if n]
    except (OSError, subprocess.CalledProcessError):
        names = [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()]
    if (root / ".kusakabe" / "app.json").exists() and ".kusakabe/app.json" not in names:
        names.append(".kusakabe/app.json")
    return sorted(n for n in set(names) if not EXCLUDE.search(n) and (root / n).is_file())


def make_tar(root: Path, names: list[str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for n in names:
            tf.add(str(root / n), arcname=n, recursive=False)
    return buf.getvalue()


# ------------------------------------------------------------------ もとにした版の記録（.kusakabe/state.json）
def load_state(root: Path) -> dict:
    """読めないときは少し待って読み直す（ほかの kdeploy が書き換えている途中のことがある。読めないまま {} を返して
    save_state で書き戻すと、もとにした版などの記録が消える）"""
    p = root / ".kusakabe" / "state.json"
    for i in range(10):
        if not p.exists():
            return {}
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            time.sleep(0.1 * (i + 1))
    raise SystemExit(f"{p} を読めません。ほかの kdeploy が動いていないか確かめてください")


def save_state(root: Path, **upd) -> dict:
    """この PC のこのフォルダだけの記録（受付には送らない。.kusakabe/.gitignore で git にも入れない）。
    一時ファイルに書いてから置き換える（書いている途中の中身をほかの kdeploy に読ませない）"""
    d = root / ".kusakabe"
    d.mkdir(parents=True, exist_ok=True)
    if not (d / ".gitignore").exists():
        (d / ".gitignore").write_text("state.json\nstate.json.*.tmp\nincoming/\n", encoding="utf-8")
    st = {**load_state(root), **upd, "updated": time.strftime("%Y-%m-%dT%H:%M:%S")}
    tmp = d / f"state.json.{os.getpid()}.tmp"
    tmp.write_text(json.dumps(st, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for i in range(10):
        try:
            os.replace(tmp, d / "state.json")
            break
        except PermissionError:   # Windows ではほかが開いている間は置き換えられない
            time.sleep(0.1 * (i + 1))
    else:
        tmp.unlink(missing_ok=True)
        raise SystemExit(f"{d / 'state.json'} を書き換えられません。ほかの kdeploy が動いていないか確かめてください")
    return st


def record_commit(root: Path, app_id: str, d: dict) -> None:
    """GitHub に記録された版を、このフォルダの「もとにした版」にする（反映の成否に関係なく main はこの版になっている）"""
    sha = d.get("commit_sha") or ""
    if sha and d.get("app_id") == app_id and load_state(root).get("base_commit") != sha:
        save_state(root, app_id=app_id, base_commit=sha, pending_deployment="")


# ------------------------------------------------------------------ 最新の版の取り込み
def safe_members(data: bytes) -> dict[str, bytes]:
    """受付から受け取った tar.gz を展開する（フォルダの外へ出るパス・リンク・ドライブ名は無視。合計と件数に上限）"""
    out, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for m in tf:
            if len(out) >= MAX_FILES:
                raise SystemExit(f"ファイルが多すぎます（{MAX_FILES} 件まで）")
            total += max(m.size, 0)
            if total > MAX_EXTRACT:
                raise SystemExit(f"展開後のソースが大きすぎます（{MAX_EXTRACT // 1024 // 1024} MB まで）")
            name = m.name.replace("\\", "/")
            while name.startswith("./"):
                name = name[2:]
            parts = name.split("/")
            if not m.isfile() or not name or name.startswith("/") or ":" in name or any(x in ("", ".", "..") for x in parts):
                continue
            f = tf.extractfile(m)
            if f:
                out[name] = f.read()
    return out


def write_files(dest: Path, files: dict[str, bytes]) -> None:
    base = dest.resolve()
    for name, data in files.items():
        p = (base / name).resolve()
        if base not in p.parents:
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def compare(root: Path, latest: dict[str, bytes]) -> tuple[list[str], list[str], list[str]]:
    """（最新の版にだけある, 両方にあって中身が違う, このフォルダにだけある）"""
    local = set(list_files(root))
    only_latest = sorted(n for n in latest if n not in local)
    changed = sorted(n for n in latest if n in local and (root / n).read_bytes() != latest[n])
    only_local = sorted(n for n in local if n not in latest)
    return only_latest, changed, only_local


def _print_list(title: str, names: list[str], limit: int = 40) -> None:
    if names:
        print(f"  {title}（{len(names)} 件）")
        for n in names[:limit]:
            print(f"    {n}")
        if len(names) > limit:
            print(f"    … ほか {len(names) - limit} 件")


# ------------------------------------------------------------------ コマンド
def cmd_init(a) -> int:
    root = Path(a.dir).resolve()
    r = api("POST", "/v1/names", {"name": a.name})
    if not r.get("ok"):
        print("この名前は使えません：" + "／".join(r.get("errors", [])))
        if r.get("suggestions"):
            print("候補：" + "、".join(r["suggestions"]))
        return 1
    p = root / ".kusakabe" / "app.json"
    if p.exists():
        cfg = json.loads(p.read_text(encoding="utf-8"))
        cfg["app_id"] = a.name
        cfg["category"] = a.name.split("-", 1)[0]
    else:
        cfg = {"app_id": a.name, "category": a.name.split("-", 1)[0], "target": a.target, "source_dir": a.source_dir,
               "auth": "m365", "cloudrun": {"memory": "512Mi", "cpu": "1", "concurrency": 40, "max_instances": 2, "timeout": 120},
               "env": {}, "secrets": {}, "probe": {"redirect": ["/"], "unauthorized": []}}
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"名前 {a.name} を予約しました（{'以前から予約済み' if r.get('already') else '新規'}）。設定：{p}")
    return 0


def cmd_files(a) -> int:
    root = Path(a.dir).resolve()
    names = list_files(root)
    for n in names:
        print(n)
    print(f"--- {len(names)} 件・{len(make_tar(root, names)) // 1024} KB（圧縮後）")
    return 0


# ------------------------------------------------------------------ 画面の事前確認（手元で起動して確かめてから出す）
def source_fingerprint(root: Path) -> str:
    """送るファイル（名前と中身）の指紋。確かめた画面と送るソースが同じかを見る
    （.kusakabe/.gitignore は記録のたびに kdeploy が作るので入れない）"""
    h = hashlib.sha256()
    for n in list_files(root):
        if n == ".kusakabe/.gitignore":
            continue
        h.update(n.encode("utf-8") + b"\0")
        h.update(hashlib.sha256((root / n).read_bytes()).digest())
    return h.hexdigest()


def _port_busy(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _kill_tree(pid: int) -> None:
    """起動したアプリを子プロセスごと止める（uvicorn --reload などは子を作るため）"""
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
    else:
        try:
            os.kill(pid, 15)
        except OSError:
            pass


def preview_check(cfg: dict, st: dict, fp: str, skip_reason: str) -> tuple[str, str]:
    """deploy の前の確認。（受付に送る記録, 止める理由）を返す。止める理由が空なら送ってよい"""
    if skip_reason.strip():
        return "skipped:" + " ".join(skip_reason.split())[:180], ""
    if cfg.get("auth") == "iam":
        return "skipped:画面のない内部 API（auth: iam）", ""
    if not isinstance(cfg.get("preview"), dict):
        return "", ("app.json に preview（手元で起動する方法）がありません。preview を書いて kdeploy preview で画面を確かめ、"
                    "利用者の OK を受けて kdeploy preview --ok を実行してから送ってください。画面に関係しない変更だけのときは "
                    '--skip-preview "理由" を付けます')
    if not st.get("preview_ok"):
        return "", "画面の確認が済んでいません。kdeploy preview で起動して利用者に確かめてもらい、OK を受けて kdeploy preview --ok を実行してください"
    if st["preview_ok"] != fp:
        return "", "画面を確かめた後にファイルが変わっています。kdeploy preview で確かめ直し、OK を受けて kdeploy preview --ok を実行してください"
    return "confirmed:" + fp, ""


def cmd_preview(a) -> int:
    root = Path(a.dir).resolve()
    cfgp = root / ".kusakabe" / "app.json"
    if not cfgp.exists():
        raise SystemExit(".kusakabe/app.json がありません。先に init で名前を予約してください")
    cfg = json.loads(cfgp.read_text(encoding="utf-8"))
    st = load_state(root)
    if a.stop:
        pid = st.get("preview_pid")
        save_state(root, preview_pid=0)   # 先に消す（起動した側はこれを見て記録に触らずに終わる）
        if pid:
            _kill_tree(int(pid))
        print("手元のアプリを止めました" if pid else "止めるものはありません")
        return 0
    fp = source_fingerprint(root)
    if a.ok:
        if not st.get("preview_started"):
            raise SystemExit("まだ kdeploy preview で起動していません")
        if st["preview_started"] != fp:
            print("画面を開いた後にファイルが変わっています。kdeploy preview を起動し直して確かめ直してください"
                  "（アプリが動かすたびに書き換わるファイルがあれば .gitignore に入れる）")
            return 4
        save_state(root, preview_ok=fp, preview_ok_at=time.strftime("%Y-%m-%dT%H:%M:%S"))
        print(f"画面の確認を記録しました（指紋 {fp[:12]}）。このまま kdeploy deploy で送れます")
        return 0
    pv = cfg.get("preview")
    if not isinstance(pv, dict) or not pv.get("command"):
        raise SystemExit('app.json に preview がありません。例：'
                         '"preview": {"command": ["py", "-3", "main.py"], "cwd": "cloudrun", "port": 8080, "path": "/", '
                         '"env": {"APP_ENV": "local", "DEV_LOGIN_EMAIL": "自分のアドレス"}}')
    port = int(a.port or pv.get("port") or 8080)
    if _port_busy(port):
        raise SystemExit(f"ポート {port} は使われています。前に起動したものなら kdeploy preview --stop で止めるか、--port で別の番号を指定してください")
    cwd = (root / (pv.get("cwd") or cfg.get("source_dir") or ".")).resolve()
    if root != cwd and root not in cwd.parents:
        raise SystemExit("preview.cwd はプロジェクトの中にしてください")
    env = {k: v for k, v in os.environ.items() if k not in ("K_SERVICE", "K_REVISION", "K_CONFIGURATION")}
    env.update({k: str(v) for k, v in (pv.get("env") or {}).items()})
    env["PORT"] = str(port)
    env.setdefault("PYTHONUTF8", "1")
    cmd = [str(c).replace("{port}", str(port)) for c in pv["command"]]
    if os.name == "nt" and cmd[0].lower() in ("python", "python3"):   # Windows の python はストアへの転送用（終了コード 49）
        cmd = ["py", "-3"] + cmd[1:]
    proc = subprocess.Popen(cmd, cwd=str(cwd), env=env)
    save_state(root, preview_started=fp, preview_ok="", preview_pid=proc.pid)
    url = f"http://localhost:{port}{pv.get('path') or '/'}"
    for _ in range(int(a.wait * 2)):
        if proc.poll() is not None:
            if load_state(root).get("preview_pid") != proc.pid:   # 起動を待つ間に preview --stop で止められた
                return 0
            print(f"アプリが起動しませんでした（終了コード {proc.returncode}）。上の表示を確かめてください")
            save_state(root, preview_pid=0)
            return 1
        if _port_busy(port):
            break
        time.sleep(0.5)
    else:
        print(f"{a.wait} 秒待っても応答がありません。起動の表示を確かめてください（起動は続けています）")
    print(f"\n画面：{url}\n確かめて OK なら kdeploy preview --ok、止めるときは Ctrl+C か kdeploy preview --stop\n", flush=True)
    try:
        rc = proc.wait()
        return 0 if load_state(root).get("preview_pid") != proc.pid else rc   # preview --stop で止めたときは正常終了
    except KeyboardInterrupt:
        _kill_tree(proc.pid)
        return 0
    finally:
        if load_state(root).get("preview_pid") == proc.pid:
            save_state(root, preview_pid=0)


def show(d: dict) -> None:
    print(f"\n状態：{d.get('status')}　{d.get('message', '')}")
    for f in d.get("blocking") or []:
        loc = f"{f.get('path', '')}{':' + str(f['line']) if f.get('line') else ''}"
        print(f"  [止める {f.get('id')}] {loc}\n      {f.get('title')}\n      → {f.get('fix')}\n      指紋 {f.get('fingerprint', '')}")
    if d.get("warnings"):
        print(f"  注意 {len(d['warnings'])} 件：")
        for f in d["warnings"][:15]:
            print(f"    [{f.get('id')}・{f.get('severity')}] {f.get('path', '')}{':' + str(f['line']) if f.get('line') else ''} {f.get('title')}")
    if d.get("commit"):
        print(f"  GitHub の記録：{d['commit']}")
    elif d.get("bcp"):
        print("  GitHub の記録：緊急モードのため後回し（復旧後に管理者が bcp ブランチで記録します）")
    if d.get("url"):
        print(f"  URL：{d['url']}")
    print(f"  デプロイ ID：{d.get('deployment_id')}")


STATUS_TIMEOUT = 180       # 状態の問い合わせ 1 回の待ち時間（受付はこの中で GitHub への記録やビルドの依頼まで進めることがある）
WAIT_LIMIT = 20 * 60       # 応答が返らないまま待つ合計の上限


def wait(dep_id: str, sleep=time.sleep, clock=time.monotonic, on_commit=None) -> int:
    """結果が出るまで状態を問い合わせる。通信のタイムアウト・切断では終わらず問い合わせ直す（受付側の処理は続いているため）。
    GitHub に記録されたら on_commit(状態) を呼ぶ（もとにした版の記録に使う）"""
    last = ""
    stalled_since = None
    while True:
        try:
            d = api("GET", f"/v1/deployments/{dep_id}", timeout=STATUS_TIMEOUT)
            stalled_since = None
        except (TimeoutError, urllib.error.URLError, ConnectionError) as e:   # 受付のエラー応答（HTTPError）は api() が SystemExit にする
            stalled_since = stalled_since or clock()
            if clock() - stalled_since > WAIT_LIMIT:
                print(f"  受付から {WAIT_LIMIT // 60} 分応答がありません。あとで kdeploy status {dep_id} で結果を確かめてください")
                return 1
            print(f"  … 受付が処理中です（応答待ち：{getattr(e, 'reason', e)}）。問い合わせ直します")
            sleep(5)
            continue
        if d.get("status") != last:
            print(f"  … {d.get('status')}　{d.get('message', '')}")
            last = d.get("status")
        if on_commit and d.get("commit_sha"):
            on_commit(d)
        if d.get("status") in TERMINAL:
            show(d)
            return 0 if d["status"] == "succeeded" else (2 if d["status"] in ("blocked", "probe_failed") else 1)
        time.sleep(5)


def cmd_deploy(a) -> int:
    root = Path(a.dir).resolve()
    cfgp = root / ".kusakabe" / "app.json"
    if not cfgp.exists():
        raise SystemExit(".kusakabe/app.json がありません。先に init で名前を予約してください")
    cfg = json.loads(cfgp.read_text(encoding="utf-8"))
    st = load_state(root)
    if st.get("incoming"):
        raise SystemExit(f"取り込んだ最新の版（{st['incoming'][:7]}）をまだ合わせていません。.kusakabe/incoming/ の内容と"
                         "自分の変更を合わせてから kdeploy merged を実行し、送り直してください")
    base = st.get("base_commit", "") if st.get("app_id") in (None, "", cfg["app_id"]) else ""
    preview, why = preview_check(cfg, st, source_fingerprint(root), a.skip_preview)
    if why:
        print("送りませんでした：" + why)
        return 4
    names = list_files(root)
    data = make_tar(root, names)
    if len(data) > MAX_BYTES:
        raise SystemExit(f"ソースが大きすぎます（{len(data) // 1024 // 1024} MB）。大きなファイルを .gitignore に入れてください")
    print(f"{cfg['app_id']} を送ります（{len(names)} ファイル・{len(data) // 1024} KB・先：{cfg.get('target')}・"
          f"もとにした版：{base[:7] or '記録なし'}{'・上書きを指定' if a.overwrite else ''}）")
    up = api("POST", "/v1/uploads")
    req = urllib.request.Request(up["url"], data=data, method="PUT", headers={"Content-Type": up.get("content_type", "application/gzip")})
    with urllib.request.urlopen(req, timeout=300) as r:
        if r.status not in (200, 201):
            raise SystemExit(f"アップロードに失敗しました（{r.status}）")
    try:
        dep = api("POST", "/v1/deployments", {"app_id": cfg["app_id"], "upload_id": up["upload_id"],
                                              "base_commit": base, "overwrite": bool(a.overwrite), "preview": preview})
    except ApiError as e:
        if e.code == 409 and isinstance(e.detail, dict) and e.detail.get("code") in ("base_conflict", "bcp_conflict", "bcp_unsettled"):
            print("送りませんでした：" + "／".join(e.detail.get("errors", [])))
            return 3
        raise
    print(f"受付が受け付けました：{dep['deployment_id']}")
    save_state(root, app_id=cfg["app_id"], pending_deployment=dep["deployment_id"])
    if a.no_wait:
        return 0
    return wait(dep["deployment_id"], on_commit=lambda d: record_commit(root, cfg["app_id"], d))


def cmd_status(a) -> int:
    """状態の確認。このフォルダから送ったデプロイなら、GitHub に記録された版をもとにした版として残す"""
    root = Path(a.dir).resolve()
    cfgp = root / ".kusakabe" / "app.json"
    mine = cfgp.exists() and load_state(root).get("pending_deployment") == a.id
    app_id = json.loads(cfgp.read_text(encoding="utf-8"))["app_id"] if mine else ""
    return wait(a.id, on_commit=(lambda d: record_commit(root, app_id, d)) if mine else None)


def cmd_pull(a) -> int:
    root = Path(a.dir).resolve()
    cfgp = root / ".kusakabe" / "app.json"
    cur = json.loads(cfgp.read_text(encoding="utf-8")).get("app_id", "") if cfgp.exists() else ""
    name = a.name or cur
    if not name:
        raise SystemExit("--name でアプリの名前を指定してください（例 --name app-website-analysis）")
    if cur and cur != name:
        raise SystemExit(f"このフォルダは {cur} です（--name {name} と違います）")
    r = api("POST", f"/v1/apps/{name}/source", timeout=180)
    sha = r["commit"]
    with urllib.request.urlopen(r["url"], timeout=300) as resp:
        data = resp.read(MAX_BYTES * 4 + 1)
    if len(data) > MAX_BYTES * 4:
        raise SystemExit("受け取ったソースが大きすぎます")
    files = safe_members(data)
    if not root.exists() or not any(root.iterdir()):
        write_files(root, files)
        save_state(root, app_id=name, base_commit=sha, incoming="")
        print(f"{name} の最新の版（{sha[:7]}・{len(files)} ファイル）を {root} に展開しました。このフォルダで編集して deploy できます")
        return 0
    st = load_state(root)
    if st.get("base_commit") == sha and not st.get("incoming"):
        print(f"このフォルダはすでに最新の版（{sha[:7]}）をもとにしています")
        return 0
    inc = root / ".kusakabe" / "incoming"
    shutil.rmtree(inc, ignore_errors=True)
    dest = inc / sha[:12]
    write_files(dest, files)
    save_state(root, app_id=name, incoming=sha)
    only_latest, changed, only_local = compare(root, files)
    print(f"{name} の最新の版（{sha[:7]}）を {dest} に置きました。このフォルダがもとにした版：{st.get('base_commit', '')[:7] or '記録なし'}")
    _print_list("最新の版にだけあるファイル（ほかの人が足した可能性。取り込まないと送ったときに消えます）", only_latest)
    _print_list("中身が違うファイル（ほかの人の変更と自分の変更を合わせる）", changed)
    _print_list("このフォルダにだけあるファイル（自分が足した、またはほかの人が消した）", only_local)
    if not (only_latest or changed or only_local):
        print("  違いはありません。kdeploy merged を実行して送り直してください")
    else:
        print("合わせ終わったら kdeploy merged を実行し、送り直してください")
    return 0


def cmd_merged(a) -> int:
    root = Path(a.dir).resolve()
    st = load_state(root)
    sha = st.get("incoming")
    if not sha:
        raise SystemExit("取り込み中の版がありません（先に kdeploy pull を実行してください）")
    dest = root / ".kusakabe" / "incoming" / sha[:12]
    latest = {p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file()} if dest.exists() else set()
    local = set(list_files(root))
    missing = sorted(latest - local)
    if missing and not a.yes:
        _print_list("最新の版にあって、このフォルダに無いファイル（このまま送ると GitHub から消えます）", missing)
        print("消してよい場合は kdeploy merged --yes、取り込む場合はこのフォルダにコピーしてから、もう一度実行してください")
        return 1
    save_state(root, base_commit=sha, incoming="")
    shutil.rmtree(root / ".kusakabe" / "incoming", ignore_errors=True)
    print(f"もとにした版を {sha[:7]} にしました。kdeploy deploy で送れます")
    return 0


def cmd_emergency(a) -> int:
    """（管理者だけ）緊急モード：GitHub が止まっている間、記録を後回しにして検査 → 反映だけを通す"""
    if a.action == "on":
        if not a.reason:
            raise SystemExit("--reason に理由を書いてください（例 --reason \"GitHub の障害で記録できない。〇〇の不具合を急ぎ直す\"）")
        r = api("POST", "/v1/admin/emergency", {"reason": a.reason, "hours": a.hours})
        print(f"緊急モードを始めました（期限 {r.get('expires', '')[:16]}・承認 {r.get('approved_by')}）。理由：{r.get('reason')}")
        print("GitHub が復旧したら kdeploy emergency off → kdeploy bcp-replay で、出した版を GitHub に戻してください")
        return 0
    if a.action == "off":
        r = api("POST", "/v1/admin/emergency/end")
        print(f"緊急モードを終えました（{r.get('ended_by')}）")
        if r.get("pending"):
            print("まだ GitHub に戻していないアプリ：" + "、".join(r["pending"]) + "。kdeploy bcp-replay で戻してください")
        return 0
    r = api("GET", "/v1/admin/emergency")
    last = r.get("last") or {}
    print(f"緊急モード：{'有効' if r.get('active') else '無効'}" + (f"（期限 {last.get('expires', '')[:16]}・理由 {last.get('reason')}）" if r.get("active") else ""))
    for x in r.get("pending") or []:
        print(f"  まだ GitHub に戻していない：{x['app_id']}（{len(x['deployments'])} 件：{', '.join(x['deployments'])}）")
    for x in r.get("open") or []:
        print(f"  main への取り込み待ち：{x['app_id']} {x.get('branch')}　{x.get('pr', '')}")
    return 0


def cmd_bcp_replay(a) -> int:
    """（管理者だけ）緊急モードで出した版を bcp/日付 ブランチに記録し、main への PR を作る"""
    r = api("POST", "/v1/admin/bcp/replay", {"app_id": a.name, "merge": bool(a.merge)}, timeout=600)
    rc = 0
    if not r.get("results"):
        print("GitHub に戻す版はありません")
    for x in r.get("results") or []:
        if x.get("error"):
            print(f"  {x['app_id']}：{x['error']}")
            rc = 1
        elif x.get("merged"):
            print(f"  {x['app_id']}：{x['branch']} に {x['commits']} 件記録し、main に入れました")
        else:
            where = ((x.get("pr") or f"PR を作る画面 {x.get('compare')}（App に PR の権限が無いため、ここから作ってください）")
                     + "。main は Ruleset で守っているので、Owner が「Merge without waiting for requirements to be met (bypass rules)」"
                       "にチェックを入れてマージしてください")
            print(f"  {x['app_id']}：{x['branch']} に {x['commits']} 件記録しました。{where}"
                  + ("　※ main は緊急モードの前から動いています。食い違いを確かめてください" if x.get("main_moved") else ""))
    return rc


def cmd_approve_auth(a) -> int:
    """（管理者だけ）auth: app-login（アプリ独自のログイン）・public（サインインなしの公開画面）での公開を承認する"""
    r = api("POST", "/v1/admin/auth-approvals", {"app_id": a.name, "type": a.type, "reason": a.reason})
    print(f"承認しました：{r.get('app_id')}（{r.get('approved_by')}）理由：{r.get('reason')}")
    return 0


def cmd_except(a) -> int:
    """（管理者だけ）検査の「止める」項目の例外を台帳に登録する（指紋は deploy の結果に表示される）"""
    r = api("POST", "/v1/admin/exceptions", {"app_id": a.name, "fingerprint": a.fingerprint, "reason": a.reason, "days": a.days})
    print(f"例外を登録しました：{r.get('app_id')} {r.get('fingerprint')}（期限 {r.get('expires', '')[:10]}）理由：{r.get('reason')}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="kdeploy")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("login")
    p.add_argument("--browser", action="store_true", help="デバイスコードではなく、ブラウザを開く方式でサインインする")
    p.add_argument("--account", default="", help="（--browser のとき）使うアカウント（例 systemadmin@kusakabe.com）")
    p.add_argument("--inprivate", action="store_true", help="（--browser のとき）Edge の InPrivate ウィンドウで開く")
    sub.add_parser("whoami")
    p = sub.add_parser("init")
    p.add_argument("--name", required=True)
    p.add_argument("--dir", default=".")
    p.add_argument("--target", default="prod", choices=["prod", "dev"])
    p.add_argument("--source-dir", default=".")
    p = sub.add_parser("deploy")
    p.add_argument("--dir", default=".")
    p.add_argument("--no-wait", action="store_true")
    p.add_argument("--overwrite", action="store_true", help="（管理者）ほかの人の更新を承知の上で、最新の版を置き換える")
    p.add_argument("--skip-preview", default="", metavar="理由",
                   help="画面の確認を省く理由（画面に関係しない変更だけのとき。GitHub の記録に残る）")
    p = sub.add_parser("preview", help="手元で起動して画面を確かめる（--ok で確認を記録、--stop で止める）")
    p.add_argument("--dir", default=".")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--wait", type=int, default=60, help="起動を待つ秒数")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--ok", action="store_true", help="利用者が画面を確かめて OK を出したことを記録する")
    g.add_argument("--stop", action="store_true", help="手元で起動したアプリを止める")
    p = sub.add_parser("status")
    p.add_argument("id")
    p.add_argument("--dir", default=".")
    p = sub.add_parser("pull", help="GitHub の最新の版を取り込む")
    p.add_argument("--dir", default=".")
    p.add_argument("--name", default="", help="アプリの名前（.kusakabe/app.json が無いフォルダに取り込むとき）")
    p = sub.add_parser("merged", help="取り込んだ版と自分の変更を合わせ終えたことを記録する")
    p.add_argument("--dir", default=".")
    p.add_argument("--yes", action="store_true", help="最新の版にあってこのフォルダに無いファイルを、消してよいものとして進める")
    p = sub.add_parser("files")
    p.add_argument("--dir", default=".")
    p = sub.add_parser("emergency", help="（管理者）緊急モード（GitHub が止まったときに記録を後回しにする）")
    p.add_argument("action", choices=["on", "off", "status"])
    p.add_argument("--reason", default="")
    p.add_argument("--hours", type=int, default=24, help="期限（時間。最大 72）")
    p = sub.add_parser("bcp-replay", help="（管理者）緊急モードで出した版を GitHub に戻す")
    p.add_argument("--name", default="", help="このアプリだけ戻す（省略すると全部）")
    p.add_argument("--merge", action="store_true", help="main が緊急モードの前から動いていなければ、PR を作らずに main に入れる")
    p = sub.add_parser("except", help="（管理者）検査の「止める」項目の例外を登録する")
    p.add_argument("--name", required=True)
    p.add_argument("--fingerprint", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--days", type=int, default=365)
    p = sub.add_parser("approve-auth", help="（管理者）アプリ独自のログイン（auth: app-login）・公開画面（auth: public）を承認する")
    p.add_argument("--name", required=True)
    p.add_argument("--type", default="app-login", choices=["app-login", "public"])
    p.add_argument("--reason", required=True)
    a = ap.parse_args()
    if a.cmd == "login":
        login(a.account, a.inprivate) if a.browser else login_device()
        _access["token"] = ""
        print("サインインしました：" + json.dumps(api("GET", "/v1/me"), ensure_ascii=False))
        return 0
    if a.cmd == "whoami":
        print(json.dumps(api("GET", "/v1/me"), ensure_ascii=False))
        return 0
    return {"init": cmd_init, "deploy": cmd_deploy, "preview": cmd_preview,"status": cmd_status, "files": cmd_files, "pull": cmd_pull,
            "merged": cmd_merged, "emergency": cmd_emergency, "bcp-replay": cmd_bcp_replay,
            "approve-auth": cmd_approve_auth, "except": cmd_except}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
