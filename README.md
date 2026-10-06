# MAWI Context Analysis

MAWI の 15 分観測窓で **1〜3 packet として観測された TCP/UDP flow** を起点に、同一 flow とその context source IP の 24 時間観測コンテキストを抽出・保存するための研究用ツールです。

重い PCAP 走査と、その後の再集約を分離しています。`extract` が再利用可能な Parquet 観測データセットを作成し、`aggregate` はコピーした dataset だけから別 PC 上でも context CSV を生成します。

## 研究上の定義

対象 flow は、指定した 15 分 PCAP 内で TCP/UDP packet を **方向非依存の双方向 5-tuple** で集約し、その観測 packet 数が設定値に一致するものです。初期解析では `1 2 3` を対象とします。

Target extraction は inactivity timeout を使いません。同じ 5-tuple の packet は、15 分窓内で長い間隔があっても同じ flow に数えます。`target_start_time` / `target_end_time` は窓内で最初／最後に観測した時刻であり、実際の通信開始／終了ではありません。

したがって「1-packet flow」は、通信の全生存期間を通して 1 packet しか存在しないという意味ではありません。正確には、**指定した 15 分観測窓において 1 packet として観測された flow** を意味します。2-packet / 3-packet も同様です。

`src_*` / `dst_*` は最初に観測した packet の方向を保持する観測値であり、client/server、initiator/responder、attacker/victim などの意味役割を自動的には表しません。

## 処理の流れ

```text
Target 15-minute PCAP
  -> bidirectional TCP/UDP 5-tuple flows
  -> shared cohort: observed packet_count in {1, 2, 3}
  -> target FlowKey / candidate context-source indexes
  -> 96 quarter-hour PCAP chunks for the same day
  -> bounded download + parallel chunk scans
  -> portable Parquet observation cache
  -> 24-hour aggregation
  -> separate schema-identical CSVs for 1 / 2 / 3 packet analysis
```

Raw extraction では Scan-like、anomaly、malicious、benign などの解釈ラベルを付与しません。観測事実を保存し、Scan-like の再定義や比較は後段の解析として行います。

## Heavy extraction と lightweight aggregation

研究室 PC では `extract` を実行します。

```bash
uv run mawi-context extract \
  --day 2026-04-08 \
  --target-chunk 202604081400 \
  --packet-counts 1 2 3 \
  --workers 1
```

この処理では、target 15 分 flow/cohort の生成、24 時間 96 chunk の取得、chunk 単位の並列 scan、Parquet cache の検証、検証済み raw PCAP の削除までを行います。

`1` は benchmark の一条件の例示です。184 GiB 研究室 Ubuntu server では real memory probe に基づき、現 indexing architecture の full-day 比較を workers `1` / `2` に限定します。Workers ≥3 は memory-gated で実行しません。Recommended workers は両条件の full-day 実測後に決めるため **TBD** です。

Default paths は実行時の working directory を基準とします。

```text
data/202604081400/
├── portable_dataset/  # コピーする durable artifacts
└── spool/             # transient raw PCAP / download ownership metadata
```

取得は最大 2 並列、通常の raw spool は `workers + 2` 枠で制限します。Worker は自分の chunk staging のみを書き、parent が検証・publication・final reload を行った後に successful raw を削除します。失敗した raw は保持します。同じ extract command の再実行では、compatible completed cache を検証して再利用し、再取得・再走査を省きます。破損や identity mismatch は明示的に失敗します。

portable dataset を別 PC にコピーした後は `aggregate` を実行します。

```bash
uv run mawi-context aggregate \
  --dataset /path/to/portable_dataset
```

`aggregate` は Internet、MAWI、元 PCAP に依存せず、portable dataset のみから 24 時間 context を再生成します。

Default results は実行時の working directory 配下です。

```text
results/202604081400/
├── packet_count_1/context.csv
├── packet_count_2/context.csv
└── packet_count_3/context.csv
```

3 CSV は同一の `CONTEXT_RESULT_COLUMNS` schema を使い、`target_flow_id` 昇順で各 `observed_packet_count` の行を出力します。同一 tuple の 24 時間／target interval 前後の packet 数と gap、TCP control packet・outbound plain SYN・inbound SYN/ACK、UDP outbound packet・宛先の種類数などは **descriptive な観測統計**です。Scan-like / anomaly の判断や意味役割の推定は downstream analysis で行います。

集約は各 Parquet を bounded batch で読み、96 files を単一 DataFrame に連結しません。Temporary SQLite は results directory に置き、成功時に削除し、失敗時は診断用に保持します。結果と temporary state は portable dataset 外に置き、dataset 自体は変更しません。

## Portable dataset

主な durable artifact は次の形式を使います。

- CSV: target-window flow table、target cohort、最終解析結果
- Parquet: packet-level raw observations
- JSON: manifest、checksum、schema/provenance metadata

Raw observation cache は 1 / 2 / 3 packet 解析で共有し、最終的な context CSV のみ packet count ごとに分けます。

```text
portable_dataset/
├── dataset_manifest.json
├── provenance/
│   ├── flows.csv
│   └── flow_manifest.json
├── cohort/
│   ├── target_cohort.csv
│   └── cohort_manifest.json
└── observations/
    ├── 202604080000/
    │   ├── target_packets.parquet
    │   ├── source_context_packets.parquet
    │   └── manifest.json
    └── ...
```

Durable manifest の artifact path は dataset-relative とし、特定 PC の絶対パスには依存させません。

`observations/` は当日 96 chunk directories を持ちます。Published chunk は immutable として扱い、checksum・exact schema・row count・cohort/source identity・provenance を検証します。コピーするのは `portable_dataset/` 全体であり、spool は不要です。

## Source context

各 target flow には `context_source_ip` と `context_source_basis` を持たせます。

- TCP: target flow 内で plain SYN sender を特定できる場合はその IP、できない場合は first-observed `src_ip`
- UDP: first-observed `src_ip`

24 時間 scan では、target 5-tuple に一致する TCP/UDP packet をすべて保存します。source context については、TCP では candidate source IP が関与する SYN / SYN+ACK / RST / FIN 系 packet、UDP では candidate source IP から送信された packet を保存します。

Application payload bytes 自体は保存しません。

`tcp_flags_raw` を canonical TCP flag fact として保存し、flag に基づく集約値は後段で計算します。

## 検証と benchmark 状態

Task 1〜7 の automated tests に加え、[synthetic CLI E2E acceptance test](tests/integration/test_end_to_end.py) が production の 96 chunk contract を検証します。Tiny synthetic PCAP と fake HTTP response を使い、extract → shared cohort/cache → valid-cache rerun → portable copy → original dataset/raw/spool removal → aggregate → 1/2/3 CSV までを通します。実 process workers を使い、schema・代表値・relative paths・解釈ラベルの不在・dataset bytes の不変性も確認します。

```bash
uv run pytest tests/integration/test_end_to_end.py -v
uv run pytest -q
```

この automated 検証は synthetic validation です。研究室の **real MAWI extraction v2 smoke は 2026-10-05 に PASSED**（target `202604081400` / non-target `202604081345`、2/96 success・94 pending・incomplete は意図通り）。**Full 24-hour benchmark は未実施**です。[Laboratory benchmark runbook](docs/benchmark.md) に従い、同一 validated raw baseline と fresh datasets で workers `1` vs `2` を比較します。Workers `3/4/8/16/32` は memory-gated / not executed で、measured failures ではありません。Full-day measurement date と recommended workers は **TBD**、Task 8B は未完了です。

## セットアップ

Python 3.12 と `uv` を使用します。

```bash
git clone https://github.com/ShuntaSakai/mawi-context-analysis.git
cd mawi-context-analysis
uv sync
```

## ディレクトリ案内

| Path | Role |
| --- | --- |
| `src/mawi_context/` | PCAP reading、flow/cohort、download、observation extraction、aggregation、CLI |
| `tests/unit/` | 各意味論・identity・scheduler の unit test |
| `tests/integration/` | cache publication、resume、portable aggregation、end-to-end validation |
| `docs/superpowers/specs/` | 承認済み設計仕様書 |
| `docs/superpowers/plans/` | 実装計画書 |
| `docs/benchmark.md` | Real V2 smoke / memory evidence、workers 1/2 full-day benchmark 手順と記録欄 |
| `notebooks/` | 後段の研究分析・可視化 |
| `data/` | portable dataset と transient spool。大容量データ本体は Git 管理外 |
| `results/` | 再生成可能な 1 / 2 / 3 packet context CSV と解析結果 |

## 設計資料

- [Approved design](docs/superpowers/specs/2026-10-04-mawi-context-analysis-design.md)
- [Implementation plan](docs/superpowers/plans/2026-10-04-mawi-context-analysis.md)

AI coding agent は変更前に [AGENTS.md](AGENTS.md) を確認してください。
