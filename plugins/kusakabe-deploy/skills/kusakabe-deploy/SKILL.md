---
name: kusakabe-deploy
description: 社内の Web アプリ（Cloud Run）を「デプロイ受付」を通して本番・検証に出すスキル。「デプロイして」「本番に出して」「公開して」「Cloud Run に出して」「受付経由でデプロイ」などのリクエストで、.kusakabe/app.json があるプロジェクト、または組織の GitHub（kusakabe-denki）で管理する Cloud Run のアプリを出すときに使う。受付が本人確認・検査（K1〜K7）・GitHub への記録・Cloud Run への反映を行う。gcloud run deploy を直接実行する代わりに使う。送る前に、手元で起動した画面を利用者に確かめてもらう（kdeploy preview）。「画面で確認して」「プレビューして」「手元で動かして」のリクエストでも使う。
---

# デプロイ受付への送信（kusakabe-deploy）

本番（apps-prod-kem）と検証（apps-dev-kem）の Cloud Run には、**デプロイ受付を通して出す**。受付が本人確認（Microsoft 365）・検査・組織の GitHub への記録・Cloud Run への反映・公開後の確認をまとめて行う。

スクリプト：`py -3 "${CLAUDE_PLUGIN_ROOT}/scripts/kdeploy.py" <コマンド>`（以下 `kdeploy`）

## 手順

1. **設定ファイルを確かめる**：プロジェクトに `.kusakabe/app.json` が無ければ初回。分類（`app`・`polaris`・`tool` ほか）と名前を利用者に確かめ、規則（接頭辞＋小文字の英数字とハイフン）どおりの名前を提案してから `kdeploy init --name <名前> --dir <プロジェクト> --source-dir <Dockerfile のあるフォルダ>` で予約する。他人と重なったら返ってきた候補から選んでもらう
2. **app.json を仕上げる**：`env` には秘密でない値だけ、`secrets` には Secret Manager の Secret の名前だけを書く（値は書かない）。Secret は先に管理者が対象のプロジェクトに作っておく（保存場所は asia-northeast1 のみ）。`probe` には、未サインインで 302 になる画面（例 `/`）と 401 になる API（例 `/api/me`）を書く。`auth` は `m365`（Microsoft 365 サインインのあるアプリ）。会社のアカウントを持たない社員も使うアプリでアプリ独自のログインにするときだけ `app-login` にし、`probe.unauthorized`（未ログインで 401 になる API）を必ず書く。`app-login` は管理者（systemadmin）が `kdeploy approve-auth --name <名前> --reason <理由>` で承認するまで送れない。サインインなしで誰でも開く画面（無記名アンケートの回答サイトなど）は `public` にし、公開しないパス（管理系の API など）で 404 になるものを `probe.not_found` に必ず書く。`public` も管理者が `kdeploy approve-auth --name <名前> --type public --reason <理由>` で承認するまで送れない
3. **送るファイルを確かめる**：`kdeploy files --dir <プロジェクト>`。`.env`・鍵・`.git`・`node_modules` は自動で外れる。余計なもの（大きなデータ等）があれば `.gitignore` に入れる
4. **サインイン（初回だけ）**：`kdeploy login` はデバイスコード方式で、ターミナルに URL（https://microsoft.com/devicelogin）とコードが出る。Claude の画面からは入力できないので、**ターミナルのパネルで実行**し（run_in_terminal）、利用者に「表示された URL をブラウザ（スマートフォンでも可）で開き、コードを入れて、デプロイに使うアカウントでサインインしてください」と伝える。この PC ではアプリがブラウザを開く方式だと QR コードの画面で止まるため、`--browser` は使わない
5. **画面を確かめてもらう（送る前に必ず）**：Cloud Run への反映は 1〜5 分かかるので、直すたびに送らない。手元で起動して利用者に確かめてもらい、OK が出てから 1 回だけ送る
   1. `app.json` に `preview` が無ければ足す：`{"command": ["py", "-3", "main.py"], "cwd": "<Dockerfile のあるフォルダ>", "port": 8080, "path": "/", "env": {"APP_ENV": "local", "DEV_LOGIN_EMAIL": "<利用者のアドレス>"}}`（`command` はそのアプリの起動方法。`{port}` はポート番号に置き換わる。`python` ではなく `py -3`）
   2. Microsoft 365 サインインのアプリは、手元ではサインインできないので**仮ログイン**を用意する：`APP_ENV == "local"` **かつ** `K_SERVICE` が無い（Cloud Run の外）ときだけ `DEV_LOGIN_EMAIL` の人として扱う（下の「仮ログインの書き方」）。画面の上に「手元の確認用」と分かる帯を出す。`APP_ENV=local`・`DEV_LOGIN_EMAIL` などは `preview.env` にだけ書く（`env` や Dockerfile に書くと受付が K4 で止める）。`preview.env` に秘密の名前（KEY・TOKEN など）は書けない（app.json は GitHub に記録される）
   3. データは本番に書き込まない。Firestore などは手元用の見本データ（メモリー上・JSON ファイル）に切り替えるか、読むだけにする
   4. `kdeploy preview --dir <プロジェクト>` を**バックグラウンドで**実行し（Bash の run_in_background）、表示された URL（`http://localhost:<ポート>/…`）をアプリ内のブラウザ（`mcp__Claude_Browser__navigate`）で開いて、変えた画面を確かめ、スクリーンショットを利用者に見せる。ブラウザのツールが無い環境では、URL を利用者に伝えて自分のブラウザで開いてもらう
   5. 利用者に「この画面で送ってよいか」を確かめる（wrap_up の質問とボタン）。直してほしい点があれば直して `kdeploy preview --stop` → もう一度起動して見てもらう。Claude が自分で見ただけで OK にしない
   6. 利用者の OK を受けたら `kdeploy preview --ok --dir <プロジェクト>` → `kdeploy preview --stop --dir <プロジェクト>`。OK の後にファイルを変えたら確かめ直し（deploy が終了コード 4 で止める）
   - 画面に関係しない変更だけ（README・設定の値・サーバー側のログの文言など）のときは、利用者に確かめた上で `kdeploy deploy --skip-preview "<理由>"`。理由は GitHub の記録に残る。画面のない内部 API（`auth: iam`）は確認不要
6. **送る**：`kdeploy deploy --dir <プロジェクト>`。結果が出るまで 1〜5 分待つ
   - 終了コード 4「画面の確認が済んでいません／確かめた後にファイルが変わっています」：手順 5 に戻る
   - 受付は、このフォルダが**もとにした版**（前回 GitHub に記録された版。`.kusakabe/state.json` に自動で残る）と GitHub の main の先頭を照らし合わせ、違えば止める（終了コード 3「ほかの人が先に更新しています」）。古い版から作ったソースで、ほかの人の変更を消さないため
7. **止められたら（終了コード 3）、最新の版を取り込んで合わせる**：
   1. `kdeploy pull --dir <プロジェクト>`：最新の版が `.kusakabe/incoming/<版>/` に置かれ、「最新の版にだけある／中身が違う／このフォルダにだけある」ファイルが表示される
   2. 中身が違うファイルは、ほかの人の変更と自分の変更の**両方を残して**このフォルダのファイルに合わせる。最新の版にだけあるファイルはこのフォルダにコピーする。同じ箇所を別々に直していて、どちらを残すか決められないときは、利用者に確かめる
   3. `kdeploy merged --dir <プロジェクト>`：最新の版にあってこのフォルダに無いファイルが残っていると止まる（送ると消えるため）。消してよいと利用者が確かめたときだけ `--yes` を付ける
   4. もう一度 `kdeploy deploy`
   - ほかの人のアプリを直すとき（管理者）は、空のフォルダに `kdeploy pull --name <アプリ名> --dir <空のフォルダ>` で最新の版を取り込んでから編集する
   - `--overwrite`（管理者だけ。最新の版を承知の上で置き換える）は、**利用者がはっきり指示したときだけ**使う。止められたときに自分の判断で付けない
8. **結果を伝える**：
   - `succeeded`：URL と GitHub の記録の URL を伝える
   - `blocked`：止められた項目（ファイル・行・直し方）を示し、利用者の了解を得て直してから送り直す。誤検知と思われるときは、指紋を添えて管理者（systemadmin）に例外の登録を依頼するよう伝える
   - `probe_failed`：公開後の確認（未サインインで 302／401）に通らなかった。前の版のまま（初回は外から入れない状態）になっている。サインインの処理を確かめて直す
   - `failed`：表示された理由を伝える。「検査の間にほかの人の更新が GitHub に入った」ときは手順 7 で取り込んでから送り直す。それ以外は管理者に連絡する
   - `error`：表示された理由を伝え、管理者に連絡する

## GitHub が止まったとき（管理者だけ・緊急モード）

GitHub の障害中は、受付が GitHub に記録できないためデプロイが 502 で失敗する。動いているアプリは影響を受けない（戻すだけなら Cloud Run の前のリビジョンへのトラフィックの切り替えで足りる）。**急ぎの修正を出す必要があるときだけ**、管理者が緊急モードを使う。

1. 利用者（管理者）に理由と期限を確かめてから `kdeploy emergency on --reason "<障害の内容と急ぐ理由>" --hours <時間（最大 72）>`。期限を過ぎると自動で通常に戻る
2. いつもどおり `kdeploy deploy`。検査は通常どおり行い、GitHub への記録だけ後回しになる（ソースは受付が保管する）。緊急モード中に同じアプリを続けて出せるのは、最初に出した人だけ
3. GitHub が復旧したら `kdeploy emergency off` → `kdeploy bcp-replay`。出した順に `bcp/日付` ブランチへ記録し、main への PR を作る（App に PR の権限が無いときは PR を作る画面の URL が出るので、管理者が GitHub で PR を作る）。main は Ruleset で守っているため、PR の通常のマージは「Merging is blocked」で止まる。Owner（kusakabe-system）が「Merge without waiting for requirements to be met (bypass rules)」にチェックを入れてからマージする（bypass は GitHub に記録される）。
   main が緊急モードの前から動いていなければ、`--merge` を付けると受付の App が main を早送りするので、PR と bypass は要らない（変更をレビューしてから入れたいときは PR にする）
4. 緊急モードで出した版が main に入るまで、そのアプリの通常のデプロイは止まる（終了コード 3）。状態は `kdeploy emergency status`

## してはいけないこと

- 画面の確認を、利用者の OK なしに `preview --ok` で済ませない。画面を変えたのに `--skip-preview` で省かない
- 検査を通すために、指摘の箇所を消す・名前を変えるなどして**検査を迂回しない**。`.security-accepted.json` に「止める」項目を書いても通らない（受付が無視する）
- 本番・検証へ `gcloud run deploy` を直接実行しない（全員の移行が終わるまでの経過措置として、利用者がはっきり指示した場合だけ。その場合も受付を勧める）
- 秘密の値を `app.json`・コード・`Dockerfile` に書かない
- 緊急モードを、GitHub が動いているときの近道に使わない（検査は同じで、記録が後回しになるだけ。止められた理由を避けるためには使わない）
- 上書き防止を迂回しない：`.kusakabe/state.json` の版を手で書き換えない。取り込んだ版を合わせずに `kdeploy merged` を実行しない
- 組織の GitHub（kusakabe-denki）のリポジトリに直接 push しない（受付と管理者だけが更新できる）

## 仮ログインの書き方（見本・Python）

```python
# 手元の画面確認（kdeploy preview）のときだけ有効。Cloud Run では K_SERVICE が必ず入るので効かない
LOCAL = os.environ.get("APP_ENV") == "local" and not os.environ.get("K_SERVICE")
DEV_LOGIN_EMAIL = os.environ.get("DEV_LOGIN_EMAIL", "").strip().lower() if LOCAL else ""

def current_user(request):
    user = user_from_session(request)          # 本来の Microsoft 365 サインイン
    if user is None and DEV_LOGIN_EMAIL:
        user = {"email": DEV_LOGIN_EMAIL, "name": "手元の確認用", "local": True}
    return user
```

- 判定は必ず「`APP_ENV == "local"` かつ `K_SERVICE` が無い」の両方にする（片方だけにしない）
- 画面の上に「手元の確認用（仮ログイン）」の帯を出し、本番の画面と見分けられるようにする
- 管理者の権限が要る画面を確かめるときは、見本データのユーザーに権限を付ける（本番の Firestore のユーザーを書き換えない）
