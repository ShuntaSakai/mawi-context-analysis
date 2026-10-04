# MAWI Context Analysis

MAWI の 15 分観測窓で **1〜3 packet として観測された TCP/UDP flow** を起点に、同一 flow とその context source IP の 24 時間観測コンテキストを抽出・保存するための研究用ツールです。

このリポジトリでは、重い PCAP 走査と、その後の軽量な再解析を明確に分離します。研究室の高性能 PC で 24 時間分の PCAP を一度だけ処理し、再利用可能な Parquet 観測データセットを作成した後は、元 PCAP や MAWI へのアクセスなしで別 PC 上でも集約・分析できることを目標とします。

## 研究上の定義

対象 flow は、指定した 15 分 PCAP 内で TCP/UDP packet を **方向非依存の双方向 5-tuple** で集約し、その観測 packet 数が設定値に一致するものです。初期解析では `1 2 3` を対象とします。

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
  --workers 16
```

この処理では、target 15 分 flow/cohort の生成、24 時間 96 chunk の取得、chunk 単位の並列 scan、Parquet cache の検証、検証済み raw PCAP の削除までを行います。

portable dataset を別 PC にコピーした後は `aggregate` を実行します。

```bash
uv run mawi-context aggregate \
  --dataset /path/to/portable_dataset
```

`aggregate` は Internet、MAWI、元 PCAP に依存せず、portable dataset のみから 24 時間 context を再生成します。

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

## Source context

各 target flow には `context_source_ip` と `context_source_basis` を持たせます。

- TCP: target flow 内で plain SYN sender を特定できる場合はその IP、できない場合は first-observed `src_ip`
- UDP: first-observed `src_ip`

24 時間 scan では、target 5-tuple に一致する TCP/UDP packet をすべて保存します。source context については、TCP では candidate source IP が関与する SYN / SYN+ACK / RST / FIN 系 packet、UDP では candidate source IP から送信された packet を保存します。

Application payload bytes 自体は保存しません。

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
| `notebooks/` | 後段の研究分析・可視化 |
| `data/` | portable dataset と transient spool。大容量データ本体は Git 管理外 |
| `results/` | 再生成可能な 1 / 2 / 3 packet context CSV と解析結果 |

## 設計資料

- [Approved design](docs/superpowers/specs/2026-10-04-mawi-context-analysis-design.md)
- [Implementation plan](docs/superpowers/plans/2026-10-04-mawi-context-analysis.md)

AI coding agent は変更前に [AGENTS.md](AGENTS.md) を確認してください。
