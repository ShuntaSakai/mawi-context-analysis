# Laboratory benchmark runbook — Task 8B

- **Full-day measurement status: Not yet run**
- **Real-data source/acquisition smoke: PASSED — extraction v2, 2026-10-05**
- **Recommended workers: TBD**
- **Measurement date: TBD**

Task 8A は repository-side の synthetic verification と手順の整備までです。
以下の full-day commands は同じ review 済み revision を使い、研究室 Ubuntu server 上で
Task 8B として実行します。Real V2 smoke と initializer memory probe の研究室実測を
以下に記録します。今回の文書更新では raw/log を再処理せず、人間から提供された
real-data evidence を記録しています。Full 24-hour benchmark は未実施で、Task 8B は未完了です。
Synthetic timing、開発 Mac の性能、CPU core 数から recommendation を作りません。

## 1. Fixed experiment and decision criteria

| Condition | Fixed value |
| --- | --- |
| Dataset day | `2026-04-08` |
| Target chunk | `202604081400` |
| Observed packet counts | `1 2 3` |
| Full-day chunks | exactly 96, `0000` through `2345` every 15 minutes |
| Full-day measured worker conditions | `1`, `2`（これから実測） |
| Memory-gated conditions | `3`, `4`, `8`, `16`, `32` — current architecture / 184 GiB machine では実行しない |
| Code | same reviewed Git commit SHA, Python environment, and dependency lock |
| Input | identical source URLs, raw size/SHA-256, and acquisition state |
| Output | a fresh dataset for every condition; no completed-cache reuse between conditions |

目的は wall time と resource pressure の実測から実用的な workers を選ぶことです。
Total wall-clock time、validated chunks/hour、CPU utilization、peak RSS、storage read
throughput、I/O wait、download/acquisition wait の evidence、failed chunks を記録します。
CPU core 数が多いという理由で最大 workers を選びません。RSS 増加、storage saturation、
I/O wait、失敗、wall time の改善幅を比較し、必要なら同条件を反復してばらつきを確認します。
同じ validated raw input と fresh output datasets で workers=1 と workers=2 を比較します。
Workers=2 の smoke 成功だけでは recommendation を決めません。両条件の full-day
wall time/resource pressure の実測が揃うまで recommended workers は **TBD** です。

### 1.1 Real initializer memory evidence and execution gate

研究室 Ubuntu server は RAM **184 GiB**、filesystem **1.8 TiB**、full-day benchmark 前の
available storage は約 **1.6 TiB** です。Storage availability は各実行直前に再取得します。
Dedicated one-worker probe は real `target_cohort.csv` を読み、production
`_initialize_scan_worker()` により `ContextIndexes` を構築しました。

| Actual one-worker probe evidence | Measured value |
| --- | --- |
| `target_cohort.csv` bytes | `5,443,849,557` |
| multiprocessing start method | `spawn` |
| VmRSS after initialization | `24,519,028 kB`（約 23.4 GiB） |
| VmHWM | `63,162,888 kB`（約 60.2 GiB） |
| `ru_maxrss` | `63,162,888 kB` |
| GNU time maximum resident set size | `63,162,888 kB` |
| GNU time elapsed initializer time | `48:49.82`（約 49 分） |
| GNU time user / system time | `2759.46 s` / `177.66 s` |
| GNU time swaps / exit status | `0` / `0` |
| Machine RAM | `184 GiB` |

Linux の上記 kB RSS 値は 1024-based として GiB 換算しています。この elapsed は
initializer だけの時間で、chunk scan / full-day wall time ではありません。
CPU utilization、I/O throughput、I/O wait はこの evidence から作りません。

| Workers | Worker-only memory: measurement or projection | Gate / actual execution evidence |
| --- | --- | --- |
| 1 | Probe 実測: steady 約 23.4 GiB、initializer high-water 約 60.2 GiB | Full-day 未測定 |
| 2 | transient 約 120 GiB、steady 約 47 GiB | Two-worker real smoke 成功。Full-day 未測定 |
| 3 | transient 約 181 GiB | 184 GiB RAM に parent / OS / page cache を加える余裕がなく unsafe、not run |
| 4 | transient 約 241 GiB | Physical RAM 超過、not run |
| 8 | steady だけでも約 187 GiB | Parent / OS / page cache を含める前に physical RAM 超過、not run |
| 16 / 32 | Worker replication はさらに増加 | Current indexing architecture では infeasible、not run |

Workers ≥2 の memory 数字は **one-worker 実測の単純乗算による安全側の resource projection**
です。同時 RSS の実測値ではなく、initializer peaks が同時に起きる envelope を想定しています。
3/4/8/16/32 は memory-gated / not executed であり、**measured failures として報告しません**。
Workers=4 を「生き残るか試す」目的で実行しません。実行条件は workers=1 / 2 に限定し、
両条件とも parent と OS を含めた resource pressure を監視します。

現在確認された scalability limit は **per-spawn-worker の in-memory `ContextIndexes`
representation** です。`spawn` は Python lookup objects を worker 間で意図的に共有せず、
各 worker が再構築します。CPU-core limitation を実証したものでも、MAWI 自体が本質的に
worker 数を制限するという結果でもありません。Compact / shared index（shared-memory / mmap
など）への置換は future architecture work で、未実装かつ今回の Task 8B benchmark の範囲外です。

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

## 3. Official source/acquisition smoke gate — PASSED, 2026-10-05

研究室 Ubuntu server の real MAWI **extraction v2** two-chunk smoke は
**REAL MAWI V2 SMOKE PASS**。Day は `2026-04-08`、target は `202604081400`、
non-target は `202604081345`、workers=2 です。

| Recorded smoke status | Value |
| --- | --- |
| success | `2` / `96` |
| pending | `94`（意図した未処理分） |
| failed | `0` |
| dataset_status | `incomplete`（2/96 smoke のため expected） |
| Decode / provenance identity | extraction `v2`, `flow-manifest-v2`, `chunk-manifest-v2` |
| Full 24-hour benchmark | Not yet run |
| Recommended workers | TBD |

Official DITL mapping の source identifiers は以下です。Local SHA/size は取得 bytes の
identity であり、publisher 提供の checksum と照合したという意味ではありません。

- Target: `https://mawi.nezu.wide.ad.jp/mawi/ditl/ditl2026/202604081400.pcap.gz`
- Non-target: `https://mawi.nezu.wide.ad.jp/mawi/ditl/ditl2026/202604081345.pcap.gz`
- Official index: [MAWI DITL 2026](https://mawi.nezu.wide.ad.jp/mawi/ditl/ditl2026/)
- Target compressed raw bytes: `7,544,700,330`
- Target SHA-256: `3f37757ca4736a11c286841b6d0001e8b8abf72892a5646867ca238357c9bbc2`

| Target facts | Rows / count |
| --- | --- |
| Total target flows | `35,864,871` |
| Shared cohort | `33,463,057` |
| Observed packet count 1 | `29,367,736` |
| Observed packet count 2 | `3,630,460` |
| Observed packet count 3 | `464,861` |
| `initial_syn_sender` basis | `22,518,978` |
| `first_observed_src` basis | `10,944,079` |
| Target `target_packets` rows | `38,023,239` |

Target rows は `29,367,736 + 2 * 3,630,460 + 3 * 464,861 = 38,023,239` と一致します。
Target flow provenance と target observation chunk の `skipped_packet_counts` は
次の map と **完全一致**しました。

| Stable reason | Target flow / target observation 共通 count |
| --- | --- |
| `capture_truncated_undecodable` | `1,134,643` |
| `ip_fragment` | `928,580` |
| `malformed_tcp_header_length` | `3` |
| `malformed_udp_length` | `2` |
| `non_ip` | `377,061` |
| `non_tcp_udp` | `57,531,267` |
| `packet_header_exceeds_declared_length` | `2` |

Non-target も成功し、`malformed_tcp_header_length: 4`、`malformed_udp_length: 1` が
記録されました。Malformed per-packet skip-and-count が target 以外の real data でも確認されました。
両 chunk は **parent final reload validation 完了後に owned raw を削除**しました。
New smoke spool は空です。Original diagnostic target raw は別途保持されています。

この結果は full-day extraction / aggregation acceptance や throughput benchmark ではありません。
Smoke evidence（log、2 chunk manifests、source identities、flow/cohort provenance、initializer
probe log）は研究室の experiment records と共に保持します。今回提供されていない evidence
path や measured Git SHA は捏造せず、元 records への参照を研究室で追記してください。

Source / code / decode identity を変更して smoke を再実施する場合は fresh directory を使い、
2-chunk laboratory harness で同じ source/provenance/schema checks と parent reload-before-delete
を確認します。Public `extract` は96 chunk固定なので2-chunk smokeには使いません。
Production の96 entry manifestは2 success / 94 pending / incompleteのまま残し、
`expected_chunk_ids()` を monkeypatch しません。Failed staging / raw は診断用に保持します。
Full-day benchmark と recommended workers は引き続き未確定です。

### 3.1 Actual portable storage evidence

| Measured smoke-v2 artifact | Reported size |
| --- | --- |
| smoke-v2 total | `18 GiB` |
| `portable_dataset` | `18 GiB` |
| Target chunk observations | `4.4 GiB` |
| Non-target chunk observations | `3.2 GiB` |
| Target `source_context_packets.parquet` | `2.9 GiB` |
| Target `target_packets.parquet` | `1.5 GiB` |
| Non-target `source_context_packets.parquet` | `3.1 GiB` |
| Non-target `target_packets.parquet` | `109 MiB` |
| `provenance` | `4.8 GiB` |
| `cohort` | `5.1 GiB` |
| New smoke spool | Empty after validated publication |

これらは丸められた **2-chunk 実測値**で、96 chunk が同じサイズになるという主張ではありません。
2-chunk average ×96 を保証された full-day portable size として扱いません。
Original diagnostic raw は別途保持されており、その容量も free-space planning に含めます。

## 4. Identical validated raw baseline

Storage に余裕がある場合の preferred baseline です。Official raw を一度だけ取得し、
各 run の spool へ同一 filesystem の hard link または reflink で準備します。
Underlying raw bytes は同じで、extract が run-specific path を unlink しても baseline
は残ります。Raw と `.download.json` の source ownership metadata を一致させます。
Baseline は immutable として扱い、in-place edits、再圧縮、truncate を禁止します。

96 compressed raw baseline と **one fresh full-day portable dataset**、staging / filesystem
overhead、logs/evidence、free-space reserve を同時に保持できることが必要です。
Full-day raw / portable の実サイズはまだ未測定です。約1.6 TiB available という snapshot
だけで fit を断定しません。安全に保持できなければ full-day comparison
を延期するか、固定した representative subset で pilot を行います。Pilot は subset IDs、
選定理由、source identity を記録し、full-day benchmark と明確に区別します。
Subset timing から full-day recommended workers を確定しません。
Public CLI は96 chunks固定なので subset pilot には別の laboratory harness が必要です。

### 4.1 Mandatory free-space gate

Baseline acquisition 前と **各 full-day run 前**に `df -h` を保存し、以下の gate を通します。
同じ Bash session で function を定義してください。別の run script を使う場合はその script に
この function と `set -euo pipefail` を読み込ませます。Budget は bytes 単位で人間が根拠を
記録して設定します。値はこの2-chunk測定から固定値として与えません。

- `RAW_REMAINING_BUDGET_BYTES`: acquisition 時は未取得 baseline 全体の保守的 budget。
  Baseline 完成後の hardlink/reflink run は `0`（既存 baseline は既に free space から除かれる）。
  Full copy が必要なら追加 raw copy 全体の capacity をここに含めます。
- `PORTABLE_BUDGET_BYTES`: one fresh full-day dataset 全体（flow/cohort を含む）の保守的 budget。
- `OVERHEAD_BUDGET_BYTES`: staging、temporary state、metadata/logs、filesystem overhead の budget。
- `FREE_RESERVE_BYTES`: 他 workload / 不確実性のため残す空き容量。ゼロにしません。

Baseline budget は確認できた source sizes / HTTP length evidence と未取得分の余裕を基にし、
portable budget は chunk size variation を見込んだ planning allowance として記録します。
これらは actual full-day size の測定値ではありません。根拠ある保守的 budget を設定できない、
または gate を通らない場合は acquisition / run を開始しません。

```bash
check_space() {
  df -h "$LAB_ROOT"
  uv run --project "$REPO" python - <<'PY'
import os
import shutil

names = ('RAW_REMAINING_BUDGET_BYTES', 'PORTABLE_BUDGET_BYTES',
         'OVERHEAD_BUDGET_BYTES', 'FREE_RESERVE_BYTES')
budgets = {}
for name in names:
    value = os.environ.get(name, '')
    if not value.isascii() or not value.isdigit():
        raise SystemExit(f'{name}: set an explicit integer byte budget')
    budgets[name] = int(value)
if any(budgets[name] <= 0 for name in names[1:]):
    raise SystemExit('portable / overhead / free reserve budgets must be positive')
free = shutil.disk_usage(os.environ['LAB_ROOT']).free
required = sum(budgets.values())
print(dict(free_bytes=free, required_free_bytes=required, budgets=budgets), flush=True)
if free < required:
    raise SystemExit('STOP: insufficient free space for baseline + one fresh dataset + reserve')
PY
}
# Export all four reviewed budgets before calling check_space; no guessed defaults.
check_space > "$LAB_ROOT/space-before-baseline.txt" 2>&1
```

Gate は開始時の capacity check です。Acquisition / scan 中も `df -h` と使用量を監視し、
budget 超過や reserve への接近が見えたら安全に中断して evidence/raw を保持します。
十分な capacity がないまま複数の full portable benchmark outputs を同時保持しません。
前 run の output を保持したいが次 run の capacity が不足する場合は、検証済み portable
dataset を別 storage にコピーして再検証するか、次 run を延期します。Cleanup の条件は §7 を参照。

Gate 通過後に baseline を取得します。

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

以下を **workers `1` と `2` のみ**に対して、一条件ずつ実行します。
例示の `WORKERS=1` を次の condition では `2` に変更します。
`RUN` は存在しない新しい directory にしてください。Workers=1 の completed cache を
workers=2 で reuse して比較することは禁止です。Workers ≥3 は実行しません。

```bash
export WORKERS=1
case "$WORKERS" in 1|2) ;; *) printf '%s\n' 'STOP: memory-gated worker count' >&2; exit 1 ;; esac
export RUN="$LAB_ROOT/runs/workers-$WORKERS"
export LINK_MODE=hardlink  # or reflink, after capability check
mkdir -p "$LAB_ROOT/runs"
mkdir "$RUN"
# Update/export the four budgets for this run; hardlink/reflink raw remaining budget is 0.
check_space > "$RUN/space-before-run.txt" 2>&1
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
cp "$LAB_ROOT/baseline-inventory.json" "$RUN/input-inventory.json"
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
開始直前にも worker gate と free-space gate を再確認します。

```bash
cd "$RUN"
case "$WORKERS" in 1|2) ;; *) printf '%s\n' 'STOP: memory-gated worker count' >&2; exit 1 ;; esac
check_space > space-at-start.txt 2>&1
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
inventory = json.loads((run/'input-inventory.json').read_text())
assert [s['chunk_id'] for s in inventory] == dm['expected_chunk_ids']
sources = {s['chunk_id']: s for s in inventory}
statuses = Counter(s['status'] for s in dm['chunks'].values())
failures = {c: s for c, s in dm['chunks'].items() if s['status'] != 'success'}
(run/'failures.json').write_text(json.dumps(failures, indent=2)+'\n')
validated = 0
for chunk, state in dm['chunks'].items():
    if state['status'] == 'success':
        checked = load_validated_chunk(root, chunk, expected_cohort_identity=dm['cohort_identity'])
        assert checked['source'] == state['source'] == sources[chunk]
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

### 7.1 Evidence preservation and human-controlled output cleanup

Workers=1 / 2 の各 condition は同じ immutable validated baseline から fresh run-specific
hardlinks/reflinks を準備し、source identity を照合して一条件ずつ走らせます。上記の
**all96 independent validation が成功してから** summary/logs、source inventory、exact command、
Git/environment、validation output、dataset / flow / cohort / 全96 chunk manifests、memory/storage
evidence を run ごとの evidence directory に保存します。Manifest 内の checksum/row-count と
その検証結果も保持し、保存先を summary に記録します。

Large Parquet output の削除は、successful independent validation と evidence 保存が済み、
**人間が比較用に不要と明示的に判断した後にのみ**可能です。この runbook は automatic
deletion command を設けません。Validation failure / incomplete の output と failed raw は
診断・再試行用に保持します。Immutable raw baseline は run cleanup で決して削除しません。
容量が足りなければ人間の判断 / 別 storage への検証済み退避を待ち、次 condition を開始しません。

## 8. Measurement record and recommendation

Full-day workers=1 / 2 は **未測定**です。その他は **memory-gated / not executed** で、
benchmark measurements ではありません。`N/A` は実行しなかった条件の metric であり、
失敗数0や measured failure を意味しません。§1.1 の probe と projections をこの full-day
table の実測 metric に転記しません。Synthetic tests の timing も記入しません。

| workers | wall_time | chunks_per_hour | avg_cpu_utilization | peak_rss | nvme_read_throughput | io_wait | download_wait_evidence | failed_chunks | full-day status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | Not yet measured |
| 2 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | 未測定 | Not yet measured |
| 3 | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | Not run — memory safety gate |
| 4 | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | Not run — projected transient memory exceeds machine RAM |
| 8 | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | Not run — projected steady worker memory exceeds machine RAM |
| 16 | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | Not run — memory safety gate |
| 32 | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | Not run — memory safety gate |

- Full-day measurement status: **Not yet run**
- Recommended workers: **TBD**
- Measurement date: **TBD**
- Measured Git commit: **TBD**
- Machine: **184 GiB RAM / 1.8 TiB filesystem**（full-day run 時に再取得、mount は TBD）
- Recommendation rationale and linked run evidence: **TBD**

各 full-day run を検証した後に実測値・units・metric definitions・measurement date・evidence paths を
記入します。Workers=1 と workers=2 の両 full-day 測定が揃ってから wall time/resource pressure
の比較により recommendation と理由を記述します。Higher worker counts は future architecture
work の条件であり、今回の completed benchmark conditions には含めません。
README の状態もその時点で更新します。各 summary、source inventory、manifest、monitor log
を卒論から追跡可能な experiment ID の下に保持してください。
