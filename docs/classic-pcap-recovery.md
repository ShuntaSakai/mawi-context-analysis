# Classic PCAP snaplen 不整合の復旧手順

Date: 2026-10-14

この手順は、2026-04-08 / target `202604081400` の既存 workers=1 dataset を
再利用し、`202604081430` と `202604082130` のみ再走査するための提案です。
**本番では未実行です。** 実装の検証は小さな synthetic PCAP のみです。
人間から報告された 94 success / 2 failed / 0 pending、188 Parquet、約181 GB
という状況を、研究室 PC 上で確認してから使います。

## 修正と互換性

Classic PCAP の `caplen > snaplen` は、`caplen <= original` で本文が完全なら
通常のデコードへ渡します。`caplen` 分を読み、切り詰め・一律 skip はしません。
新たに許容する超過レコードは 16 MiB 以下に限定し、それを超えるものは本文を
読む前に `CaptureError` にします。従来受理できた `caplen <= snaplen` のレコードには
この新しい上限を適用しません。既存の巨大 snaplen 経路全体の安全性改善は対象外です。
ヘッダ・タイムスタンプ・レコード境界・本文切断・gzip の検証は保持し、
PCAPNG の snaplen 検証も保持します。

Extraction `v2`、`flow-manifest-v2`、`chunk-manifest-v2` を維持します。
旧パーサで成功した capture は snaplen 超過を含められず、その入力で新パーサの
CaptureRecord とデコード結果は変わりません。失敗 chunk には成功 cache がありません。
したがって既存94 chunk、`flows.csv`、`target_cohort.csv` を厳密検証して再利用できます。
単純な v3 化は dataset / target provenance の一致検証と aggregation を止めます。
現 manifest は exact keys / equality 検証なので、追記による再ラベル付けもしません。
[設計書 §§2.6・9.1](superpowers/specs/2026-10-04-mawi-context-analysis-design.md) を参照してください。

V2 identity 単独では正確なパーサ改訂を識別できません。新旧のコード証拠は
**dataset 外の recovery audit bundle** に記録し、dataset の持ち運び時も併せて保存します。
旧実行の Git SHA / diff / 環境は当時の benchmark 証拠から取得します。不明な値は
`unknown` と明示し、新コードで再抽出したかのような provenance を作らないでください。
今回のポリシー名は `classic-pcap-snaplen-tolerance-2026-10-14` です。

## 1. 事前の読み取り専用確認

同じ dataset / spool を扱う extract、benchmark、cleanup が動いていないことを
確認します。全工程を一つの parent が占有する運用にしてください。修正コードの
配備と fixture tests の成功を確認し、workers は `1` に固定します。Parent の target
CSV 検証と worker の cohort 初期化は大きなメモリを要します。94 cache の検証は
全 Parquet の checksum と全行を読みますが、raw の再解析ではありません。
前処理・再開時・最終確認でこの I/O と CSV 読み込みを繰り返す時間を見込んでください。

実際の研究室 repository path を指定します。以下は既存研究データを変更しません。
環境変数を設定するだけで、再抽出は開始しません。

```bash
export MAWI_RECOVERY_REPO=/absolute/path/to/mawi-context-analysis
export MAWI_RECOVERY_DATASET=/home/s-sakai/mawi-task8b/runs/workers-1/data/202604081400/portable_dataset
export MAWI_RECOVERY_SPOOL=/home/s-sakai/mawi-task8b/runs/workers-1/data/202604081400/spool
export MAWI_RECOVERY_BASELINE=/home/s-sakai/mawi-task8b/baseline
cd "$MAWI_RECOVERY_REPO"
git branch --show-current
git status --short
df -h "$MAWI_RECOVERY_DATASET" "$MAWI_RECOVERY_SPOOL"
```

空き容量には新しい2 chunk分の Parquet、staging、ログ、余裕を含めます。
Baseline `/home/s-sakai/mawi-task8b/baseline` の2 raw が、spool の raw と同じ
SHA-256 / size で保存されていることも確認します。Baseline の内容・permission・
ファイル名は変更しません。Baseline に確認済みの複製がない場合、成功後の spool
削除で唯一の raw を失わないよう、別途保存する方法について人間に確認してください。

以下の Python は Internet にアクセスせず、既存 provenance と94 cacheを production
validator で検証します。失敗2 chunkの raw ownership は SHA-256 / size / URL を検証し、
dataset の以前の source identity と一致させます。Ownership metadata が欠損・不一致なら
中止し、手作業で生成・修正しないでください。余分な staging / raw / `.part` も自動削除しません。

```bash
.venv/bin/python - <<'PY'
from dataclasses import asdict
import json
import os
from pathlib import Path
from mawi_context import extraction as ex
from mawi_context.chunks import render_ditl_chunk_url
from mawi_context.downloader import _owned_source, _paths
from mawi_context.hashing import sha256_file
from mawi_context.manifests import load_json_object

options = ex.ExtractOptions('2026-04-08', '202604081400', (1, 2, 3), 1,
    Path(os.environ['MAWI_RECOVERY_DATASET']), Path(os.environ['MAWI_RECOVERY_SPOOL']))
root = options.dataset_root
baseline = Path(os.environ['MAWI_RECOVERY_BASELINE']).resolve()
assert not root.is_relative_to(baseline) and not options.spool_root.is_relative_to(baseline)
assert root != options.spool_root
ids = ex.expected_chunk_ids(options.day)
failed = {'202604081430', '202604082130'}
assert (root/'dataset_manifest.json').is_file() and not (root/'dataset_manifest.json').is_symlink()
dm = load_json_object(root/'dataset_manifest.json')
ex._validate_dataset_state(dm, ex._dataset_header(options, ids, dm.get('cohort_identity')))
assert dm['status'] == 'incomplete'
assert {c for c, s in dm['chunks'].items() if s['status'] == 'failed'} == failed
assert sum(s['status'] == 'success' for s in dm['chunks'].values()) == 94
assert not any(s['status'] == 'pending' for s in dm['chunks'].values())
assert {p.name for p in (root/'observations').iterdir()} == set(ids)-failed
# Guard the validator's reuse path: missing provenance must never bootstrap.
for directory, names in [('provenance', {'flows.csv', 'flow_manifest.json'}),
                         ('cohort', {'target_cohort.csv', 'cohort_manifest.json'})]:
    assert (root/directory).is_dir() and not (root/directory).is_symlink()
    assert {p.name for p in (root/directory).iterdir()} == names
source, identity = ex._target_provenance(options, render_ditl_chunk_url,
    dm['chunks'][options.target_chunk]['source'])
assert identity == dm['cohort_identity']
hashes = {}
for directory, manifest_name in [('provenance', 'flow_manifest.json'),
                                  ('cohort', 'cohort_manifest.json')]:
    relative = directory+'/'+manifest_name
    manifest = load_json_object(root/relative)
    hashes[relative] = sha256_file(root/relative)
    hashes[manifest['artifact']['path']] = manifest['artifact']['sha256']
for chunk in ids:
    url = render_ditl_chunk_url(options.day, chunk)
    raw, metadata, part = _paths(chunk, options.spool_root)
    assert not os.path.lexists(part), ('partial raw requires diagnosis', chunk)
    if chunk in failed:
        assert not os.path.lexists(root/'observations'/chunk)
        owned = _owned_source(chunk, url, options.spool_root)
        assert owned is not None and asdict(owned) == dm['chunks'][chunk]['source']
        assert _owned_source(chunk, url, baseline) == owned
        continue
    # No completed-cache raw may be deleted incidentally in this two-raw recovery.
    assert not os.path.lexists(raw) and not os.path.lexists(metadata)
    manifest = ex.load_validated_chunk(root, chunk, expected_cohort_identity=identity)
    assert manifest['source'] == dm['chunks'][chunk]['source']
    assert manifest['source']['source_url'] == url
    if chunk == options.target_chunk:
        assert manifest['source'] == asdict(source)
        fm = load_json_object(root/'provenance/flow_manifest.json')
        assert manifest['skipped_packet_counts'] == fm['skipped_packet_counts']
    hashes[f'observations/{chunk}/manifest.json'] = sha256_file(root/f'observations/{chunk}/manifest.json')
    for artifact in manifest['artifacts'].values():
        hashes[artifact['path']] = artifact['sha256']
print(json.dumps({'policy': 'classic-pcap-snaplen-tolerance-2026-10-14',
    'dataset_state_before': dm, 'immutable_artifact_sha256': hashes,
    'failed_raw_sources': {c: dm['chunks'][c]['source'] for c in sorted(failed)}},
    indent=2, sort_keys=True))
PY
```

すべて成功しても本番パーサで両 real capture を最後まで処理した証拠ではありません。
この確認結果、過去の独立診断（56 / 31 超過、gzip・EOF・SHA一致）、baseline の証拠、
資源余裕、配備したコード証拠を人間が確認します。異常があればここで止めます。

## 2. 書き込みと raw 削除を含む操作の確認

**以下の本番操作はユーザーの確認後にだけ実行します。この修正作業では実行しません。**
確認対象は「既存 workers-1 dataset を使った2 chunkの復旧、parent の dataset progress
更新、新しい2 cacheの publication、および検証後の spool raw / metadata 2組の削除」です。
CLI に raw を保持するオプションや chunk filter はありません。この削除も含めた承認が
得られなければ開始しません。`run_full_day_benchmark.sh` は再実行しません。

確認後、dataset 外の新規 audit directory に次を保存します。既存 audit を上書きせず、
コード証拠の Git SHA だけでなく未commit diffを必ず含めます。

- 事前確認の JSON（上の出力）、実行前 `dataset_manifest.json` のコピー、failed2組の
  `.download.json` のコピー。CSV / 94 chunk の hash一覧は事前確認 JSON に含まれます。
- 旧実行の revision / diff / 環境証拠、または不足している項目と `unknown` の明記。
- `git rev-parse HEAD`、`git diff --binary HEAD`、`git status --short`、修正済み
  `src/mawi_context/*.py` と `pyproject.toml` / `uv.lock` の SHA-256。
  未追跡コードがある場合は diff に含まれないのでその内容も保存します。
- Python / uv / pandas / pyarrow のバージョン、fixture test 結果、実行 command、
  開始終了時刻、終了コード、stdout/stderr、資源の記録。

Audit directory は `portable_dataset/` / `spool/` / `baseline/` の外に置きます。
監査証拠・ログ保存も含めて準備した後、再度他プロセスが動いていないことと
事前確認以降に研究データ・コードが変わっていないことを確認します。

## 3. 承認後の再開コマンド

Cwd は repository ではなく **既存 workers-1 run directory** にします。
`--project` は配備済みコードの選択であり、default dataset/spool の基準は cwd です。
事前確認に使った `MAWI_RECOVERY_DATASET` / `MAWI_RECOVERY_SPOOL` と一致させます。
依存関係が準備済みの環境で `--offline --no-sync` を使います。

```bash
cd /home/s-sakai/mawi-task8b/runs/workers-1
uv run --offline --no-sync --project "$MAWI_RECOVERY_REPO" mawi-context extract \
  --day 2026-04-08 \
  --target-chunk 202604081400 \
  --packet-counts 1 2 3 \
  --workers 1
```

実行結果と exit code は audit directory に保存します。Code は96 chunk を計画しますが、
94 chunk は checksum / schema / row count / cohort/source identity / skip provenance を
検証して再利用し、raw を取得・再走査しません。Target provenance も既存 CSV を
読み込み、checksum・schema・flow/cohortの整合性を確認して再利用します。
Failed2 chunkの matching owned raw を再使用し、worker は自分の staging にだけ書きます。
事前確認済みの状態が維持されていれば download は発生しません。Raw がなくなるなど
状態が変われば通常 CLI は取得を試み得るため、確認後の同時作業は禁止です。
厳密にネットワークを防ぐ必要があれば、実行環境の egress 制限も確認してください。

## 4. 成功の確認と削除条件

Exit 0 だけで完了とせず、production validator で全96 chunkを再検証します。
`load_validated_chunk(..., expected_cohort_identity=...)` は source / artifact checksum /
exact schema / row count / skip mapを検証します。各 chunk の source を dataset state と
照合し、target chunk の skip mapを flow provenance と照合します。

事前確認 JSON を audit directory の `before.json` に保存した場合、次は読み取り専用の
最終確認です。`MAWI_RECOVERY_AUDIT` は確認後に作成した dataset 外の audit directory
を指定します。集約の内部 validator を呼びますが、集約結果は生成しません。

```bash
cd "$MAWI_RECOVERY_REPO"
.venv/bin/python - <<'PY'
from dataclasses import asdict
import json
import os
from pathlib import Path
from mawi_context.aggregation import _validate_dataset
from mawi_context.downloader import _owned_source, _paths
from mawi_context.hashing import sha256_file
from mawi_context.manifests import load_json_object

root = Path(os.environ['MAWI_RECOVERY_DATASET']).resolve()
spool = Path(os.environ['MAWI_RECOVERY_SPOOL']).resolve()
baseline = Path(os.environ['MAWI_RECOVERY_BASELINE']).resolve()
before = load_json_object(Path(os.environ['MAWI_RECOVERY_AUDIT'])/'before.json')
dm, _ = _validate_dataset(root)  # Includes all96 cache and target provenance validation.
assert dm['cohort_identity'] == before['dataset_state_before']['cohort_identity']
assert len(dm['chunks']) == 96 and all(s['status'] == 'success' for s in dm['chunks'].values())
for chunk, state in before['dataset_state_before']['chunks'].items():
    assert dm['chunks'][chunk]['source'] == state['source']
for relative, digest in before['immutable_artifact_sha256'].items():
    assert sha256_file(root/relative) == digest, ('immutable artifact changed', relative)
new_manifests = {}
for chunk, source in before['failed_raw_sources'].items():
    assert dm['chunks'][chunk]['source'] == source
    for path in _paths(chunk, spool):
        assert not os.path.lexists(path), ('unexpected spool file', path)
    owned = _owned_source(chunk, source['source_url'], baseline)
    assert owned is not None and asdict(owned) == source
    relative = f'observations/{chunk}/manifest.json'
    new_manifests[relative] = sha256_file(root/relative)
print(json.dumps({'status': dm['status'], 'validated_chunks': len(dm['chunks']),
    'new_manifest_sha256': new_manifests, 'dataset_state_after': dm}, indent=2, sort_keys=True))
PY
```

Audit に次を保存します。

- Dataset `success`、96 success / 0 failed / 0 pending、source identity の不変性。
- `flows.csv`、`target_cohort.csv`、両 provenance manifest、既存94 chunkの全3ファイルが
  事前の `immutable_artifact_sha256` と同じ SHA-256 であること。
- 新2 chunkの manifestとSHA-256、全192 Parquetの検証結果、skipped counts。
  Snaplen超過自体を skip count に追加せず、デコードできない packet は既存理由で数えます。
- Failed2組の spool raw / metadata が削除済みであり、baseline の raw は同じ hashで残ること。
  新2 manifestの source identity が事前の `failed_raw_sources` と一致すること。
- 実行後 `dataset_manifest.json` と stdout/stderr / timing / exit code。

Raw削除は worker 成功だけでは起きません。Parent が staging を検証し、exclusive rename
で publish し、final cache を独立再ロード検証して sourceも照合した後、
`_delete_owned_raw()` が raw ownership / size / SHA-256 を再照合して unlink します。
Published94 cache、target provenance、baseline はこの処理の削除対象ではありません。
後段の `aggregate` は完成した portable dataset のみで実行できますが、この復旧の
承認には集約処理を含めません。

## 5. 失敗・中断とロールバック

Worker の decode/container/write 失敗なら raw と ownership evidence は保持され、
新しい final cache は作られません。Parent の staging/final 検証失敗時は、この parent
自身が publish した inode のみ staging に戻す rollback を試み、raw削除には進みません。
Rollback は best effort なので、例外・残った final / staging の実状態を確認してください。
既存94 cacheは上書きしません。Spoolの唯一の rawを手作業で削除しないでください。

Run全体の transaction / 全部取り消しはありません。一方が成功して他方が失敗した場合、
成功した新 cache は保持され、その raw は既に削除され得ます。旧 dataset_manifest を
単にコピーし直すと published cache と progress の整合性を損なうため、手動復元しません。
進捗manifestは parent が更新した不完全状態のまま保存し、診断後、その時点の成功数と
残りfailedに合わせて読み取り専用確認をやり直し、残りだけを再開する承認を取ります。
最初の94/2状態を前提にした事前確認は、95/1の状態では意図的に停止します。

Raw と metadata の unlink は2操作です。電源断等で rawだけ消えて metadataが残る
可能性があり、次回 ownership validation は安全側に失敗します。Baseline を保持し、
その復旧は別途人間の確認を得てください。Identity mismatch、checksum異常、未知の
artifact、ownership欠損があれば再ラベル付け・再生成・検証省略で通さず、証拠を保存して止めます。

## ローカル検証記録

- RED: capture / resume tests、旧コードで **29 failed / 117 passed**。
  超過レコード受理・切断診断・安全上限・復旧が従来のsnaplen検証で失敗。
- GREEN: 同じ範囲で **146 passed**。
- 全suite: **672 passed**。Fixture の96 chunk復旧は94 cacheとtarget provenanceの
  バイト不変、2 chunkだけのscan、downloadなし、parent reload前のraw保持と検証後の削除を確認。
- この文書の事前確認・最終確認 Python も別の tiny synthetic 96 chunk datasetで実行。
  94/2状態の確認成功、raw ownership / Parquet checksum不一致の拒否、復旧後96 cacheと
  既存286 artifact hashの不変性を確認。独立レビューでも修正を要する指摘なし。
- 実行commandは `UV_CACHE_DIR=/tmp/mawi-snaplen-uv-cache uv run --offline --no-sync pytest ...`。
  通常のuv cacheがsandbox書き込み制約により使用できなかったため、一時cacheを使用。
- Real MAWI 2 captureの amended extractorでの処理、独立パーサとの全件比較、
  研究室artifactの実地検証は未実施です。
