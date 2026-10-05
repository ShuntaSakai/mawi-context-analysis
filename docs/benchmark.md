# Laboratory benchmark runbook — Task 8B

- **Measurement status: Not yet run**
- **Real-data source/acquisition smoke: Not yet run（未実施）**
- **Recommended workers: TBD**
- **Measurement date: TBD**

Task 8A は repository-side の synthetic verification と手順の整備までです。
以下の commands は人間による review/push 後、研究室 Ubuntu server 上で
Task 8B として実行します。この文書の作成時点では実MAWIをdownloadしていません。
Synthetic timing、開発 Mac の性能、CPU core 数から recommendation を作りません。

## 1. Fixed experiment and decision criteria

| Condition | Fixed value |
| --- | --- |
| Dataset day | `2026-04-08` |
| Target chunk | `202604081400` |
| Observed packet counts | `1 2 3` |
| Full-day chunks | exactly 96, `0000` through `2345` every 15 minutes |
| Scan workers | `1`, `4`, `8`, `16`, `32` |
| Code | same reviewed Git commit SHA, Python environment, and dependency lock |
| Input | identical source URLs, raw size/SHA-256, and acquisition state |
| Output | a fresh dataset for every condition; no completed-cache reuse between conditions |

目的は wall time と resource pressure の実測から実用的な workers を選ぶことです。
Total wall-clock time、validated chunks/hour、CPU utilization、peak RSS、storage read
throughput、I/O wait、download/acquisition wait の evidence、failed chunks を記録します。
CPU core 数が多いという理由で最大 workers を選びません。RSS 増加、storage saturation、
I/O wait、失敗、wall time の改善幅を比較し、必要なら同条件を反復してばらつきを確認します。

Flow は target 15 分窓内の direction-independent bidirectional TCP/UDP 5-tuple、
inactivity timeout なしです。1/2/3 はその窓内の観測数で、全通信の lifetime size
ではありません。TCP context source は observed plain-SYN sender があればその IP、
なければ first-observed src、UDP は first-observed src を使います。
Benchmark のために cohort、retention、schema、identity、deletion prerequisites を変えません。

## 2. Environment and evidence directory

以下は Bash 用です。`REPO` は review 済み checkout、`LAB_ROOT` は dataset/spool を
置く十分な容量のある研究室 storage に設定します。新しい実験ごとに新しい directory を
使います。CPU/RAM/storage は run 時に取得し、記憶上の machine specs を代入しません。

```bash
set -euo pipefail
export REPO=/absolute/path/to/mawi-context-analysis
export LAB_ROOT=/absolute/path/on/lab/storage/mawi-task8b
mkdir -p "$LAB_ROOT"
cd "$REPO"
uv sync --locked
git status --short --branch > "$LAB_ROOT/git-status.txt"
git rev-parse HEAD > "$LAB_ROOT/commit.txt"
git diff > "$LAB_ROOT/working-tree.diff"
# Review the status/diff; use the same clean reviewed revision for all runs.
{
  date --iso-8601=seconds
  date -u --iso-8601=seconds
  uname -a
  uv run python --version
  uv --version
  lscpu
  free -h
  lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL
  df -h "$LAB_ROOT" "$REPO"
  findmnt -T "$LAB_ROOT"
  for tool in /usr/bin/time pidstat iostat vmstat; do
    command -v "$tool" || true
  done
  /usr/bin/time --version
  pidstat -V
  iostat -V
  vmstat -V
} > "$LAB_ROOT/environment.txt" 2>&1
cp uv.lock pyproject.toml "$LAB_ROOT/"
```

`findmnt` / `lsblk` で dataset/spool の mount と underlying device を特定し、
`iostat` のどの device を read-throughput 集計に使うか記録します。NVMe 以外なら
table の `nvme_read_throughput` 欄に実際の device/type を注記します。
`time`、`pidstat`、`iostat`、`vmstat` がなければ、Ubuntu の `time` / `sysstat` /
`procps` または equivalent を用意し、availability/version と代替手法を記録してから進みます。
他 workload、power policy、OS page-cache の扱い、run order を notes に記録します。
Warm/cold cache を混ぜて比較しません。全条件を同じ warm-cache policy で実行する、
または管理者と合意した cache-control procedure を全条件に適用します。

## 3. Official source/acquisition smoke gate（未実施）

全96 chunkを取得する前に、target と non-target `202604081345` の2 chunkだけを
official DITL mapping で取得し、実 bytes を検証します。現在の mapping は
`render_ditl_chunk_url()` が生成する次の URL です。

- Target: `https://mawi.nezu.wide.ad.jp/mawi/ditl/ditl2026/202604081400.pcap.gz`
- Non-target: `https://mawi.nezu.wide.ad.jp/mawi/ditl/ditl2026/202604081345.pcap.gz`
- Official index: [MAWI DITL 2026](https://mawi.nezu.wide.ad.jp/mawi/ditl/ditl2026/)

Task 8B 実行時に official index と上記 mapping を照合し、その確認内容・時刻・
HTTP response evidence を保存します。404 や unexpected source は URL を推測して
回避せず、smoke failure として調査します。Local SHA/size は取得 bytes の identity
であり、publisher 提供の checksum と照合したという意味ではありません。

Public `extract` は必ず96 chunkを処理するため、2-chunk smoke に使いません。
以下は pinned revision の内部 API を使う laboratory-only harness です。
Production `expected_chunk_ids()` を monkeypatch せず、96 entry の manifest を
`incomplete` のまま残します。これは full-day extraction / aggregation acceptance
や workers throughput benchmark ではありません。

```bash
uv run --project "$REPO" python - <<'PY' > "$LAB_ROOT/smoke.log" 2>&1
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict
import os
from pathlib import Path
import tempfile
import pandas as pd
import pyarrow.parquet as pq
from mawi_context import extraction as ex, downloader as dl, observations as obs
from mawi_context.cohort import COHORT_COLUMNS, select_target_cohort
from mawi_context.flow import FLOW_COLUMNS
from mawi_context.hashing import sha256_file
from mawi_context.manifests import load_json_object, write_json_atomically

base = Path(os.environ['LAB_ROOT']) / 'smoke'
base.mkdir(exist_ok=False)
o = ex.ExtractOptions('2026-04-08', '202604081400', (1, 2, 3), 2,
                      base/'portable_dataset', base/'spool')
ids = ex.expected_chunk_ids(o.day)
assert len(ids) == 96
target_source, identity = ex._target_provenance(o, ex.render_ditl_chunk_url)
flows = ex._read_csv(o.dataset_root/'provenance/flows.csv', FLOW_COLUMNS)
cohort = ex._read_csv(o.dataset_root/'cohort/target_cohort.csv', COHORT_COLUMNS)
pd.testing.assert_frame_equal(cohort, select_target_cohort(flows, (1, 2, 3)).reset_index(drop=True),
                              check_dtype=False, check_exact=True)
fm = load_json_object(o.dataset_root/'provenance/flow_manifest.json')
cm = load_json_object(o.dataset_root/'cohort/cohort_manifest.json')
assert fm['flow_definition'] == ex.FLOW_DEFINITION
assert fm['flow_definition']['inactivity_timeout'] is None
assert cm['context_source_policy'] == ex.CONTEXT_SOURCE_POLICY
assert set(cohort.observed_packet_count) <= {1, 2, 3}
print('target flow counts:', flows.packet_count.value_counts().to_dict())
print('cohort counts:', cohort.observed_packet_count.value_counts().to_dict())
print('context source bases:', cohort.context_source_basis.value_counts().to_dict())
states = {c: {'status': 'pending'} for c in ids}
header = ex._dataset_header(o, ids, identity)
manifest_path = o.dataset_root/'dataset_manifest.json'
write_json_atomically(manifest_path, dict(header, status='incomplete', chunks=states))
sources = [target_source, obs.RawSourceIdentity(**dl.download_chunk(
    '202604081345', ex.render_ditl_chunk_url(o.day, '202604081345'), o.spool_root))]
parent = o.dataset_root/'observations'
parent.mkdir()
with ProcessPoolExecutor(max_workers=2, initializer=ex._initialize_scan_worker,
                         initargs=(str(o.dataset_root/'cohort/target_cohort.csv'),)) as pool:
    tasks = []
    for source in sources:
        raw, metadata, _ = dl._paths(source.chunk_id, o.spool_root)
        assert raw.stat().st_size == source.size_bytes
        assert sha256_file(raw) == source.sha256
        assert load_json_object(metadata) == asdict(source)
        print('acquired:', asdict(source), flush=True)
        stage = Path(tempfile.mkdtemp(prefix=f'.staging-{source.chunk_id}-', dir=parent))
        task = ex.ScanChunkTask(source.chunk_id, raw, stage, o.dataset_root, source, identity)
        tasks.append((task, pool.submit(ex._scan_chunk_worker, task)))
    for task, future in tasks:
        result = future.result()
        # Production parent validation -> publication -> independent final reload -> deletion.
        manifest = ex._finish_chunk(task, result, o)
        checked = obs.load_validated_chunk(o.dataset_root, task.chunk_id,
                                           expected_cohort_identity=identity)
        assert checked == manifest and checked['source'] == asdict(task.source)
        for name, schema in [('target_packets', obs.TARGET_PACKET_SCHEMA),
                             ('source_context_packets', obs.SOURCE_CONTEXT_SCHEMA)]:
            assert pq.read_schema(parent/task.chunk_id/f'{name}.parquet').equals(schema, check_metadata=True)
        raw, metadata, _ = dl._paths(task.chunk_id, o.spool_root)
        assert not raw.exists() and not metadata.exists()
        states[task.chunk_id] = dict(status='success', source=manifest['source'],
                                     manifest=f'observations/{task.chunk_id}/manifest.json')
        write_json_atomically(manifest_path, dict(header, status='incomplete', chunks=states))
        print('parent reloaded and successful raw deleted:', task.chunk_id, flush=True)
ex._validate_dataset_state(load_json_object(manifest_path), header)
assert len([s for s in states.values() if s['status'] == 'success']) == 2
assert list(o.spool_root.iterdir()) == []
print('SMOKE PASS: 2/96 chunks; full-day measurement NOT performed')
PY
```

Smoke log、2 chunk manifests、source identities、flow/cohort provenance を人間が
確認して gate を通します。失敗時は staging と raw を診断用に保持し、`_finish_chunk`
失敗を raw deletion で回避しません。実データの各 packet count が0行ならその事実を
記録し、membership を作り替えません。成功しても measurement status は full benchmark
が終わるまで Not yet run のままです。

## 4. Identical validated raw baseline

Storage に余裕がある場合の preferred baseline です。Official raw を一度だけ取得し、
各 run の spool へ同一 filesystem の hard link または reflink で準備します。
Underlying raw bytes は同じで、extract が run-specific path を unlink しても baseline
は残ります。Raw と `.download.json` の source ownership metadata を一致させます。
Baseline は immutable として扱い、in-place edits、再圧縮、truncate を禁止します。

96 compressed raw と全 run の Parquet datasets、ログ、temporary state の容量を
確認してください。実サイズは未測定です。96 raw を保持できなければ full-day comparison
を延期するか、固定した representative subset で pilot を行います。Pilot は subset IDs、
選定理由、source identity を記録し、full-day benchmark と明確に区別します。
Subset timing から full-day recommended workers を確定しません。
Public CLI は96 chunks固定なので subset pilot には別の laboratory harness が必要です。

```bash
uv run --project "$REPO" python - <<'PY' > "$LAB_ROOT/baseline-acquisition.log" 2>&1
import json
import os
from pathlib import Path
from mawi_context.chunks import expected_chunk_ids, render_ditl_chunk_url
from mawi_context.downloader import download_chunk, _owned_source, _paths

root = Path(os.environ['LAB_ROOT'])/'baseline'
root.mkdir(exist_ok=False)
inventory = []
for chunk in expected_chunk_ids('2026-04-08'):
    url = render_ditl_chunk_url('2026-04-08', chunk)
    facts = download_chunk(chunk, url, root)
    assert _owned_source(chunk, url, root) is not None  # reload size/SHA/ownership
    inventory.append(facts)
    print(json.dumps(facts), flush=True)
    raw, metadata, _ = _paths(chunk, root)
    raw.chmod(0o444)
    metadata.chmod(0o444)
assert len(inventory) == 96
(root.parent/'baseline-inventory.json').write_text(json.dumps(inventory, indent=2)+'\n')
PY
```

これは download identity validation です。全96 captures の packet decode/Parquet validation
は各 extract run で行います。途中取得失敗なら inventory が完成したと扱わず、matching
owned raw を残して acquisition を再開します（再開時のみ `mkdir(exist_ok=True)`）。
HTTP header evidence が必要なら smoke/acquisition 時の transport log を別途保存します。

Hardlink は異なる filesystem 間では使えません。Benchmark前に raw baseline の試験用
file で `ln` または `cp --reflink=always` が成功するか確認し、method と mount を記録します。
Reflink unsupported を `--reflink=auto` で黙って full copy にしません。
Full copy が必要なら全条件で同じ method を使い、SHA検証・copyの時間は測定区間外に置きます。

## 5. Prepare a fresh run for each worker condition

以下を workers `1 4 8 16 32` に対して実行します。例示の `WORKERS=1` を毎回変更します。
`RUN` は存在しない新しい directory にしてください。Workers=1 の completed cache を
workers=4 で reuse して比較することは禁止です。

```bash
export WORKERS=1
export RUN="$LAB_ROOT/runs/workers-$WORKERS"
export LINK_MODE=hardlink  # or reflink, after capability check
mkdir -p "$LAB_ROOT/runs"
mkdir "$RUN"
test "$(git -C "$REPO" rev-parse HEAD)" = "$(cat "$LAB_ROOT/commit.txt")"
test -z "$(git -C "$REPO" status --porcelain)"
mkdir -p "$RUN/data/202604081400/spool"
uv run --project "$REPO" python - <<'PY' > "$RUN/input-validation.log" 2>&1
from dataclasses import asdict
import json
import os
from pathlib import Path
import shutil
import subprocess
from mawi_context.chunks import expected_chunk_ids, render_ditl_chunk_url
from mawi_context.downloader import _owned_source, _paths

baseline = Path(os.environ['LAB_ROOT'])/'baseline'
spool = Path(os.environ['RUN'])/'data/202604081400/spool'
inventory = json.loads((baseline.parent/'baseline-inventory.json').read_text())
assert [s['chunk_id'] for s in inventory] == list(expected_chunk_ids('2026-04-08'))
for facts in inventory:
    chunk = facts['chunk_id']
    url = render_ditl_chunk_url('2026-04-08', chunk)
    source = _owned_source(chunk, url, baseline)
    assert source is not None and asdict(source) == facts
    raw, metadata, _ = _paths(chunk, baseline)
    destination, owned_metadata, _ = _paths(chunk, spool)
    if os.environ['LINK_MODE'] == 'hardlink':
        os.link(raw, destination)
    elif os.environ['LINK_MODE'] == 'reflink':
        subprocess.run(['cp', '--reflink=always', str(raw), str(destination)], check=True)
    else:
        raise ValueError('choose a tested hardlink or reflink method')
    shutil.copy2(metadata, owned_metadata)
    assert _owned_source(chunk, url, spool) == source
    print(json.dumps(facts), flush=True)
assert not (spool.parent/'portable_dataset').exists()
PY
```

Target raw を含む all96 の matching ownership records が必須です。現実装は
preexisting owned raw が `workers + 2` より多くても、既存 raw を順次 scan できます。
Target が存在するので bootstrap は追加取得せず target provenance を構築できます。
この baseline preparation は通常の bounded download spool を変更しません。
Missing/mismatched raw は測定前に失敗させ、network acquisition 混入を防ぎます。

## 6. Measured run and monitor lifecycle

Run-specific cwd が default dataset/spool を分離します。`uv sync` と input preparation
は測定前に完了させます。以下を Bash script として実行し、同一手順で各条件を測ります。
`trap` は error / interrupt 時も monitor を停止し、`wait` で回収します。

```bash
cd "$RUN"
monitor_pids=()
stop_monitors() {
  for pid in "${monitor_pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${monitor_pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  monitor_pids=()
}
trap stop_monitors EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

pidstat -h -u -r -d -p ALL 1 > pidstat.log 2>&1 &
monitor_pids+=("$!")
iostat -y -x -m -t 1 > iostat.log 2>&1 &
monitor_pids+=("$!")
vmstat -w -t 1 > vmstat.log 2>&1 &
monitor_pids+=("$!")
printf '%s\n' "${monitor_pids[@]}" > monitor-pids.txt
for pid in "${monitor_pids[@]}"; do kill -0 "$pid"; done

command=(uv run --project "$REPO" mawi-context extract
  --day 2026-04-08 --target-chunk 202604081400
  --packet-counts 1 2 3 --workers "$WORKERS")
printf '%q ' "${command[@]}" > command.txt
printf '\n' >> command.txt
date --iso-8601=seconds > start.txt
ps -eo pid,ppid,lstart,args > processes-before.txt
start_ns=$(date +%s%N)
set +e
/usr/bin/time -v -o time.txt "${command[@]}" > stdout.log 2> stderr.log
exit_code=$?
set -e
end_ns=$(date +%s%N)
date --iso-8601=seconds > end.txt
printf '%s\n' "$exit_code" > exit-code.txt
printf '%s %s\n' "$start_ns" "$end_ns" > wall-nanoseconds.txt
ps -eo pid,ppid,lstart,args > processes-after.txt
stop_monitors
trap - EXIT INT TERM
cp data/202604081400/portable_dataset/dataset_manifest.json dataset_manifest.json
```

保存する evidence は exact command、stdout/stderr、GNU time output、monitor PID と logs、
start/end、exit code、dataset manifest、input inventory、Git SHA、failure details です。
Target acquisition 自体で失敗し manifest がない場合も stdout/stderr と missing manifest の
事実を保存し、成功 run として扱いません。Monitor が終了してログが取れない condition は
その不足を明示し、measurement をやり直す場合は fresh run directory を使います。

`pidstat` は parent/worker と他プロセスを含むため、実験中の process tree も記録すると
CPU/RSS attribution を追跡しやすくなります。必要なら別 terminal で
`ps -eo pid,ppid,lstart,args` を run 中に採取して `processes-during.txt` に保存します。
GNU time の Maximum resident set size は並列 process family の同時 RSS 合計を保証しません。
Table の peak RSS には GNU time 値とその定義を記録し、可能なら dedicated cgroup の
memory peak または timestamp-aligned parent+worker RSS の sampled peak を併記します。
Cgroup memory は page cache を含み得るため RSS と同じ値として扱いません。
CPU は process family の合計（100% = one logical CPU）か host全体の平均かを必ず明記します。
Storage throughput と I/O wait は monitor interval と device、host-level measurement を明記します。
`vmstat` の初回 report は boot 以来の平均なので interval 平均の集計から除外し、
start/end 時刻内の samples を使います。CPU と throughput は同じ測定区間の samples の
平均、RSS は選んだ定義の最大値として集計し、sampling interval と単位を notes に残します。

## 7. Independent post-run validation and summary

測定区間終了後、parent が作った output を独立に再検証します。Failed raw は削除せず
保持します。以下の summary は failure/pending と検証失敗を隠さず記録します。

```bash
uv run --project "$REPO" python - <<'PY' > "$RUN/validation.log" 2>&1
from collections import Counter
import json
import os
from pathlib import Path
from mawi_context import aggregation as ag
from mawi_context.chunks import expected_chunk_ids
from mawi_context.manifests import load_json_object
from mawi_context.observations import load_validated_chunk

run = Path(os.environ['RUN'])
root = run/'data/202604081400/portable_dataset'
dm = load_json_object(root/'dataset_manifest.json')
assert dm['expected_chunk_ids'] == list(expected_chunk_ids('2026-04-08'))
statuses = Counter(s['status'] for s in dm['chunks'].values())
failures = {c: s for c, s in dm['chunks'].items() if s['status'] != 'success'}
(run/'failures.json').write_text(json.dumps(failures, indent=2)+'\n')
validated = 0
for chunk, state in dm['chunks'].items():
    if state['status'] == 'success':
        load_validated_chunk(root, chunk, expected_cohort_identity=dm['cohort_identity'])
        validated += 1
start, end = map(int, (run/'wall-nanoseconds.txt').read_text().split())
seconds = (end-start)/1e9
summary = dict(workers=int(os.environ['WORKERS']), wall_seconds=seconds,
               validated_chunks=validated, chunks_per_hour=validated*3600/seconds,
               statuses=dict(statuses), failed_chunks=statuses['failed'],
               pending_chunks=statuses['pending'], dataset_status=dm['status'])
(run/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
print(json.dumps(summary, indent=2), flush=True)
assert int((run/'exit-code.txt').read_text()) == 0
assert dm['status'] == 'success' and validated == 96
ag._validate_dataset(root)  # checksum/schema/row count/source/cohort/provenance, portable only
assert list((root.parent/'spool').iterdir()) == []
print('ALL96 independently validated; successful raw/spool empty')
PY
```

同じ condition を resume して診断する場合は、その時間を fresh-run comparison へ混ぜません。
Incomplete run の chunks/hour は validated数を分子とし、pending と failed を分けて報告します。
Successful full-day は `96 * 3600 / wall_seconds` です。
Extraction は詳細な download-wait timer を提供していないため、存在しない metric を作りません。
Baseline comparison では input validation が all96 matching owned raw を示すことと、network
の追加取得がなかったことを acquisition evidence として記録します。必要なら lab の network
monitor / trace を追加し、手法とログを保存します。別途 Internet acquisition を含む run は
network condition と wait evidence を記録し、pre-staged scan comparison と区別します。

## 8. Measurement record and recommendation

以下はすべて **未測定**です。Synthetic tests の timing は記入しません。

| workers | wall_time | chunks_per_hour | avg_cpu_utilization | peak_rss | nvme_read_throughput | io_wait | download_wait_evidence | failed_chunks | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | Not yet run |
| 4 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | Not yet run |
| 8 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | Not yet run |
| 16 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | Not yet run |
| 32 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | Not yet run |

- Measurement status: **Not yet run**
- Recommended workers: **TBD**
- Measurement date: **TBD**
- Measured Git commit: **TBD**
- Machine/mount: **TBD**
- Recommendation rationale and linked run evidence: **TBD**

Task 8B 完了後にのみ実測値・units・metric definitions・measurement date・evidence paths を
記入し、wall time/resource pressure の比較から recommendation と理由を記述します。
README の状態もその時点で更新します。各 summary、source inventory、manifest、monitor log
を卒論から追跡可能な experiment ID の下に保持してください。
