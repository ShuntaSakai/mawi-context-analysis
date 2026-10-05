"""Portable-only descriptive aggregation with bounded disk-backed state.

All durable evidence is validated before ingestion. Only cohort/provenance
frames and one Parquet batch are held in Python memory; packet facts, indexes,
and set-based metric tables live in temporary SQLite state outside the dataset.
"""
import argparse
import csv
from dataclasses import asdict, dataclass
import ipaddress
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import tempfile

import pandas as pd
import pyarrow.parquet as pq

from mawi_context.chunks import expected_chunk_ids, validate_target_chunk
from mawi_context.cohort import COHORT_COLUMNS, build_context_indexes, select_target_cohort
from mawi_context.flow import Endpoint, FLOW_COLUMNS, FlowKey
from mawi_context.manifests import (
    artifact_record, cohort_identity, load_json_object, resolve_artifact_path,
    validate_skipped_packet_counts,
)
from mawi_context.observations import (
    CHUNK_MANIFEST_SCHEMA_VERSION, SOURCE_CONTEXT_SCHEMA_VERSION,
    TARGET_PACKET_SCHEMA_VERSION, RawSourceIdentity, load_validated_chunk,
)


_BATCH_SIZE = 4096
_COHORT_RESULT_COLUMNS = (
    'target_flow_id', 'observed_packet_count', 'ip_version', 'protocol',
    'src_ip', 'src_port', 'dst_ip', 'dst_port', 'target_start_time',
    'target_end_time', 'target_duration', 'context_source_ip', 'context_source_basis',
)
_TARGET_METRIC_COLUMNS = (
    'same_tuple_packet_count_24h', 'same_tuple_before_count',
    'same_tuple_target_interval_count', 'same_tuple_after_count',
    'previous_same_tuple_timestamp', 'previous_same_tuple_gap_seconds',
    'next_same_tuple_timestamp', 'next_same_tuple_gap_seconds',
    'same_tuple_before_1s_count', 'same_tuple_after_1s_count',
    'same_tuple_before_10s_count', 'same_tuple_after_10s_count',
    'same_tuple_before_60s_count', 'same_tuple_after_60s_count',
    'same_tuple_before_300s_count', 'same_tuple_after_300s_count',
)
_TCP_METRICS = (
    'tcp_control_packet_count', 'tcp_outbound_plain_syn_count',
    'tcp_inbound_syn_ack_count', 'tcp_outbound_rst_count', 'tcp_inbound_rst_count',
    'tcp_outbound_fin_count', 'tcp_inbound_fin_count',
    'tcp_outbound_unique_dst_ip_count', 'tcp_outbound_unique_dst_port_count',
    'tcp_outbound_unique_dst_ip_port_count',
)
_UDP_METRICS = (
    'udp_outbound_packet_count', 'udp_outbound_unique_dst_ip_count',
    'udp_outbound_unique_dst_port_count', 'udp_outbound_unique_dst_ip_port_count',
)
_HORIZONS = ('24h', 'window_60s', 'window_300s')
CONTEXT_RESULT_COLUMNS = (
    *_COHORT_RESULT_COLUMNS, *_TARGET_METRIC_COLUMNS,
    *(f'{metric}_{horizon}' for horizon in _HORIZONS for metric in _TCP_METRICS),
    *(f'{metric}_{horizon}' for horizon in _HORIZONS for metric in _UDP_METRICS),
)

# Durable extraction v2 identities, checked locally without importing acquisition.
_FLOW_DEFINITION = {
    'protocols': [6, 17], 'key': 'direction-independent-bidirectional-5-tuple',
    'inactivity_timeout': None, 'src_dst': 'first-observed-packet-direction',
}
_CONTEXT_SOURCE_POLICY = {
    'tcp': 'initial-plain-syn-sender-else-first-observed-src', 'udp': 'first-observed-src',
}
_TOOL_IDENTITY = {'name': 'mawi-context-analysis', 'version': '0.1.0', 'extraction': 'v2'}
_OBSERVATION_VERSIONS = {
    'target_packets': TARGET_PACKET_SCHEMA_VERSION,
    'source_context_packets': SOURCE_CONTEXT_SCHEMA_VERSION,
    'chunk_manifest': CHUNK_MANIFEST_SCHEMA_VERSION,
}


@dataclass(frozen=True)
class AggregateOptions:
    dataset_root: Path
    output_root: Path | None = None


def _require_keys(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f'invalid {label} structure')


def _packet_counts(value):
    if (not isinstance(value, list) or not value
            or any(type(n) is not int or n <= 0 for n in value)
            or len(set(value)) != len(value)):
        raise ValueError('packet_counts must contain unique positive integers')
    return tuple(value)


def _source(value):
    _require_keys(value, ('chunk_id','source_url','sha256','size_bytes'), 'source identity')
    return RawSourceIdentity(**value)


def _read_validated_csv(root, relative, columns, version, record):
    _require_keys(record, ('path','sha256','row_count','schema_version'), 'CSV artifact')
    if (record['path'] != relative or record['schema_version'] != version
            or type(record['row_count']) is not int or record['row_count'] < 0):
        raise ValueError('CSV artifact path/version/row count mismatch')
    path = resolve_artifact_path(root, relative)
    # Check the literal header before pandas can mangle duplicate column names.
    with path.open(newline='', encoding='utf-8') as stream:
        if tuple(next(csv.reader(stream), ())) != columns:
            raise ValueError('CSV columns mismatch')
    strings = {c:'string' for c in columns if c.endswith('_ip') or c=='context_source_basis'}
    times = {c:'float64' for c in columns if c.endswith('_time') or c.endswith('duration')}
    integers = {c:'Int64' for c in columns if c not in strings and c not in times}
    frame = pd.read_csv(path, dtype={**strings, **times, **integers}, float_precision='round_trip')
    nullable = {c for c in columns if c.startswith('initial_syn_')}
    if frame[[c for c in columns if c not in nullable]].isna().any().any():
        raise ValueError('CSV required fact is null')
    for column in integers:
        if column not in nullable:
            frame[column] = frame[column].astype('int64')
        else:
            frame[column] = pd.Series((None if pd.isna(v) else int(v) for v in frame[column]), dtype=object)
    if artifact_record(root,path,row_count=len(frame),schema_version=version) != record:
        raise ValueError('CSV checksum/row count/identity mismatch')
    return frame


def _validate_flow_facts(flows):
    if flows.flow_id.le(0).any() or flows.flow_id.duplicated().any() or flows.packet_count.le(0).any():
        raise ValueError('invalid flow IDs/counts')
    for row in flows.itertuples(index=False):
        FlowKey.from_packet(row.src_ip,row.src_port,row.dst_ip,row.dst_port,row.protocol)
        for direction in ('src','dst'):
            ip = getattr(row,direction+'_ip')
            if ipaddress.ip_address(ip).version != row.ip_version:
                raise ValueError('flow IP version mismatch')
        if (not all(math.isfinite(v) for v in (row.start_time,row.end_time,row.duration))
                or row.duration != row.end_time-row.start_time):
            raise ValueError('invalid flow observational interval')
        for role in ('sender','receiver'):
            ip = getattr(row,'initial_syn_'+role+'_ip')
            port = getattr(row,'initial_syn_'+role+'_port')
            if pd.isna(ip) != pd.isna(port):
                raise ValueError('partial SYN endpoint')
            if not pd.isna(ip):
                Endpoint(ip,port)
    if not flows.empty:
        cohort_identity(select_target_cohort(flows,tuple(int(v) for v in flows.packet_count.unique())))


def _validate_dataset(root):
    """Return cohort facts only after independently validating all 96 caches."""
    if not root.is_dir():
        raise ValueError('dataset_root must be an existing directory')
    path = root/'dataset_manifest.json'
    if path.is_symlink() or not path.is_file():
        raise ValueError('dataset_manifest.json must be a regular file')
    dm = load_json_object(path)
    _require_keys(dm, (
        'manifest_schema_version','day','target_chunk','packet_counts','cohort_identity',
        'expected_chunk_ids','flow_manifest','cohort_manifest','observation_schemas',
        'tool','status','chunks',
    ), 'dataset manifest')
    ids = expected_chunk_ids(dm['day'])
    validate_target_chunk(dm['day'], dm['target_chunk'])
    counts = _packet_counts(dm['packet_counts'])
    identity = dm['cohort_identity']
    if not isinstance(identity,str) or re.fullmatch('[0-9a-f]{64}',identity) is None:
        raise ValueError('cohort identity must be a lowercase SHA-256')
    if (dm['manifest_schema_version'] != 'dataset-manifest-v1' or dm['status'] != 'success'
            or dm['expected_chunk_ids'] != list(ids) or dm['tool'] != _TOOL_IDENTITY
            or dm['observation_schemas'] != _OBSERVATION_VERSIONS):
        raise ValueError('dataset status/version/chunks/tool identity mismatch')
    if not isinstance(dm['chunks'],dict) or set(dm['chunks']) != set(ids):
        raise ValueError('dataset must contain exactly the expected 96 chunk states')
    for field,relative in [('flow_manifest','provenance/flow_manifest.json'),
                           ('cohort_manifest','cohort/cohort_manifest.json')]:
        if dm[field] != relative:
            raise ValueError('provenance manifest path mismatch')
        resolve_artifact_path(root,dm[field])
    for directory,names in [('provenance',{'flows.csv','flow_manifest.json'}),
                            ('cohort',{'target_cohort.csv','cohort_manifest.json'})]:
        d = root/directory
        if (d.is_symlink() or not d.is_dir() or {p.name for p in d.iterdir()} != names
                or any(p.is_symlink() or not p.is_file() for p in d.iterdir())):
            raise ValueError('invalid target provenance files')
    fm = load_json_object(root/dm['flow_manifest'])
    cm = load_json_object(root/dm['cohort_manifest'])
    _require_keys(fm, ('manifest_schema_version','status','target_chunk','source',
                       'flow_definition','tool','artifact','skipped_packet_counts'), 'flow manifest')
    _require_keys(cm, ('manifest_schema_version','status','target_chunk','source','packet_counts',
                       'context_source_policy','cohort_identity','tool','artifact'), 'cohort manifest')
    validate_skipped_packet_counts(fm['skipped_packet_counts'])
    source = _source(fm['source'])
    if (source.chunk_id != dm['target_chunk'] or cm['source'] != asdict(source)
            or fm['manifest_schema_version'] != 'flow-manifest-v2'
            or cm['manifest_schema_version'] != 'cohort-manifest-v1'
            or fm['flow_definition'] != _FLOW_DEFINITION
            or cm['context_source_policy'] != _CONTEXT_SOURCE_POLICY
            or _packet_counts(cm['packet_counts']) != counts or cm['cohort_identity'] != identity
            or any(m['target_chunk'] != dm['target_chunk'] or m['status'] != 'success'
                   or m['tool'] != _TOOL_IDENTITY for m in (fm,cm))):
        raise ValueError('flow/cohort provenance identity mismatch')
    flows = _read_validated_csv(root,'provenance/flows.csv',FLOW_COLUMNS,'flows-v1',fm['artifact'])
    cohort = _read_validated_csv(root,'cohort/target_cohort.csv',COHORT_COLUMNS,'cohort-v1',cm['artifact'])
    _validate_flow_facts(flows)
    if cohort.target_flow_id.duplicated().any() or cohort_identity(cohort) != identity:
        raise ValueError('cohort identity mismatch')
    try:
        pd.testing.assert_frame_equal(cohort,select_target_cohort(flows,counts).reset_index(drop=True),
                                      check_dtype=False,check_exact=True)
    except AssertionError as error:
        raise ValueError('cohort facts disagree with target flow provenance') from error
    # Preserve capture-first/capture-last timestamps. A reversed selected
    # interval cannot partition the observations under the specified predicates.
    # Non-cohort flow timestamps impose no aggregation interval constraint.
    if cohort.target_start_time.gt(cohort.target_end_time).any():
        raise ValueError('target interval start exceeds end; cannot partition observations')
    for chunk in ids:
        state = dm['chunks'][chunk]
        _require_keys(state, ('status','source','manifest'), 'chunk state')
        if state['status'] != 'success' or state['manifest'] != f'observations/{chunk}/manifest.json':
            raise ValueError('chunk status/manifest path mismatch')
        resolve_artifact_path(root,state['manifest'])
        if _source(state['source']).chunk_id != chunk:
            raise ValueError('chunk state source mismatch')
        manifest = load_validated_chunk(root,chunk,expected_cohort_identity=identity)
        if manifest['source'] != state['source']:
            raise ValueError('chunk source disagrees with dataset state')
        if chunk == dm['target_chunk']:
            if manifest['source'] != asdict(source):
                raise ValueError('target chunk source disagrees with provenance')
            if manifest['skipped_packet_counts'] != fm['skipped_packet_counts']:
                raise ValueError('target chunk skip counts disagree with flow provenance')
    return dm, cohort


def _create_tables(db):
    db.executescript('''
        PRAGMA temp_store=FILE;
        PRAGMA cache_size=-16384;
        CREATE TABLE cohort (
            target_flow_id INTEGER PRIMARY KEY, observed_packet_count INTEGER,
            ip_version INTEGER, protocol INTEGER, src_ip TEXT, src_port INTEGER,
            dst_ip TEXT, dst_port INTEGER, target_start_time REAL, target_end_time REAL,
            target_duration REAL, context_source_ip TEXT, context_source_basis TEXT
        );
        CREATE TABLE target (target_flow_id INTEGER, timestamp REAL);
        CREATE TABLE source (timestamp REAL, protocol INTEGER, src_ip TEXT,
                             src_port INTEGER, dst_ip TEXT, dst_port INTEGER, tcp_flags_raw INTEGER);
    ''')


def _ingest_observations(db, root, ids, cohort):
    indexes = build_context_indexes(cohort)
    versions = dict(zip(cohort.target_flow_id,cohort.ip_version))
    for name in ('target_packets','source_context_packets'):
        for chunk in ids:
            with pq.ParquetFile(root/'observations'/chunk/f'{name}.parquet') as parquet:
                for batch in parquet.iter_batches(batch_size=_BATCH_SIZE):
                    rows = batch.to_pylist()  # bounded by _BATCH_SIZE, never a whole file/day
                    if name == 'target_packets':
                        for row in rows:
                            key = FlowKey.from_packet(row['src_ip'],row['src_port'],
                                row['dst_ip'],row['dst_port'],row['protocol'])
                            if (indexes.target_flow_by_key.get(key) != row['target_flow_id']
                                    or versions.get(row['target_flow_id']) != row['ip_version']):
                                raise ValueError('target observation does not match cohort FlowKey/protocol')
                            if not math.isfinite(row['timestamp']):
                                raise ValueError('target observation timestamp must be finite')
                        db.executemany('INSERT INTO target VALUES (?,?)',
                                       ((r['target_flow_id'],r['timestamp']) for r in rows))
                    else:
                        for row in rows:
                            if (not math.isfinite(row['timestamp']) or row['protocol'] not in (6,17)
                                    or (row['protocol']==6 and row['tcp_flags_raw'] is None)):
                                raise ValueError('invalid source observation facts')
                            candidates = indexes.candidate_source_ips
                            if row['protocol'] == 6:
                                retained = (bool(row['tcp_flags_raw'] & 0x07)
                                            and (row['src_ip'] in candidates or row['dst_ip'] in candidates))
                            else:
                                retained = row['src_ip'] in candidates
                            if not retained:
                                raise ValueError('source observation violates retained packet retention policy')
                        db.executemany('INSERT INTO source VALUES (?,?,?,?,?,?,?)',
                            ((r['timestamp'],r['protocol'],r['src_ip'],r['src_port'],
                              r['dst_ip'],r['dst_port'],r['tcp_flags_raw']) for r in rows))
                    db.commit()  # preserve completed batches in a diagnostic DB on failure


def _source_expressions(protocol):
    # Length-prefix the address, followed by an integer port: injective even
    # for IPv6. The pair is an SQL DISTINCT key, never a persisted identity.
    pair = "printf('%d:%s:%d',length(o.dst_ip),o.dst_ip,o.dst_port)"
    outbound = 'o.outbound=1'
    expressions = []
    if protocol == 6:
        expressions.append('COUNT(o.timestamp)')
        for condition in (
            f'{outbound} AND (o.tcp_flags_raw & 2)!=0 AND (o.tcp_flags_raw & 16)=0',
            'o.inbound=1 AND (o.tcp_flags_raw & 2)!=0 AND (o.tcp_flags_raw & 16)!=0',
            f'{outbound} AND (o.tcp_flags_raw & 4)!=0',
            'o.inbound=1 AND (o.tcp_flags_raw & 4)!=0',
            f'{outbound} AND (o.tcp_flags_raw & 1)!=0',
            'o.inbound=1 AND (o.tcp_flags_raw & 1)!=0',
        ):
            expressions.append(f'COUNT(CASE WHEN {condition} THEN 1 END)')
    else:
        expressions.append('COUNT(o.timestamp)')
    for key in ('o.dst_ip','o.dst_port',pair):
        expressions.append(f'COUNT(DISTINCT CASE WHEN {outbound} THEN {key} END)')
    return expressions


def _compute_metrics(db):
    """A fixed number of GROUP BY statements, independent of cohort size."""
    db.executescript('''
        CREATE INDEX target_id_time ON target(target_flow_id,timestamp);
        CREATE INDEX source_src_time ON source(protocol,src_ip,timestamp);
        CREATE INDEX source_dst_time ON source(protocol,dst_ip,timestamp);
        CREATE INDEX cohort_source ON cohort(protocol,context_source_ip);
    ''')
    before = 'o.timestamp<c.target_start_time'
    after = 'o.timestamp>c.target_end_time'
    previous = f'MAX(CASE WHEN {before} THEN o.timestamp END)'
    next_ = f'MIN(CASE WHEN {after} THEN o.timestamp END)'
    expressions = [
        'COUNT(o.timestamp)', f'COUNT(CASE WHEN {before} THEN 1 END)',
        'COUNT(CASE WHEN o.timestamp>=c.target_start_time AND o.timestamp<=c.target_end_time THEN 1 END)',
        f'COUNT(CASE WHEN {after} THEN 1 END)', previous, f'c.target_start_time-{previous}',
        next_, f'{next_}-c.target_end_time',
    ]
    for n in (1,10,60,300):
        expressions.extend([
            f'COUNT(CASE WHEN o.timestamp>=c.target_start_time-{n} AND {before} THEN 1 END)',
            f'COUNT(CASE WHEN {after} AND o.timestamp<=c.target_end_time+{n} THEN 1 END)',
        ])
    select = ','.join(f'{expr} AS {column}' for column,expr in zip(_TARGET_METRIC_COLUMNS,expressions))
    db.execute(f'''CREATE TABLE target_metrics AS SELECT c.target_flow_id,{select}
        FROM cohort c LEFT JOIN target o ON o.target_flow_id=c.target_flow_id GROUP BY c.target_flow_id''')
    # One row per relevant source endpoint in SQL, with a self-address packet
    # represented once and both direction predicates retained. Shared source
    # 24h metrics are computed once, then reused by every target flow.
    db.executescript('''
        CREATE TABLE source_endpoints AS
        SELECT s.*,s.src_ip AS context_source_ip,1 AS outbound,
               CASE WHEN s.src_ip=s.dst_ip THEN 1 ELSE 0 END AS inbound
        FROM source s
        UNION ALL
        SELECT s.*,s.dst_ip AS context_source_ip,0 AS outbound,1 AS inbound
        FROM source s WHERE s.protocol=6 AND s.src_ip!=s.dst_ip;
        CREATE INDEX endpoint_time ON source_endpoints(protocol,context_source_ip,timestamp);
    ''')
    for protocol, prefix, columns in [(6,'tcp',_TCP_METRICS),(17,'udp',_UDP_METRICS)]:
        select = ','.join(f'{expr} AS {column}' for column,expr in zip(columns,_source_expressions(protocol)))
        db.execute(f'''CREATE TABLE {prefix}_24h AS
            SELECT c.context_source_ip,{select}
            FROM (SELECT DISTINCT context_source_ip FROM cohort WHERE protocol={protocol}) c
            LEFT JOIN source_endpoints o ON o.protocol={protocol} AND o.context_source_ip=c.context_source_ip
            GROUP BY c.context_source_ip''')
        db.execute(f'CREATE UNIQUE INDEX {prefix}_source ON {prefix}_24h(context_source_ip)')
        for n in (60,300):
            db.execute(f'''CREATE TABLE {prefix}_{n}s AS SELECT c.target_flow_id,{select}
                FROM cohort c LEFT JOIN source_endpoints o
                  ON o.protocol={protocol} AND o.context_source_ip=c.context_source_ip
                  AND o.timestamp>=c.target_start_time-{n} AND o.timestamp<=c.target_end_time+{n}
                WHERE c.protocol={protocol} GROUP BY c.target_flow_id''')
            db.execute(f'CREATE UNIQUE INDEX {prefix}_{n}s_id ON {prefix}_{n}s(target_flow_id)')
    db.execute('CREATE UNIQUE INDEX target_metrics_id ON target_metrics(target_flow_id)')
    db.commit()


def _result_rows(db, packet_count=None):
    fields = [f'c.{name}' for name in _COHORT_RESULT_COLUMNS]
    fields.extend(f't.{name}' for name in _TARGET_METRIC_COLUMNS)
    joins = ['LEFT JOIN target_metrics t USING(target_flow_id)']
    for prefix,columns in [('tcp',_TCP_METRICS),('udp',_UDP_METRICS)]:
        for horizon,table in [('24h',f'{prefix}_24h'),('window_60s',f'{prefix}_60s'),('window_300s',f'{prefix}_300s')]:
            alias = f'{prefix}_{horizon}'
            key = 'context_source_ip' if horizon=='24h' else 'target_flow_id'
            protocol = 6 if prefix=='tcp' else 17
            joins.append(f'LEFT JOIN {table} {alias} ON {alias}.{key}=c.{key} AND c.protocol={protocol}')
            fields.extend(f'COALESCE({alias}.{column},0)' for column in columns)
    where = 'WHERE c.observed_packet_count=?' if packet_count is not None else ''
    return db.execute(f"SELECT {','.join(fields)} FROM cohort c {' '.join(joins)} {where} ORDER BY c.target_flow_id",
                      (packet_count,) if packet_count is not None else ())


def _write_result_group(db, count, path):
    with path.open('w',newline='',encoding='utf-8') as stream:
        writer = csv.writer(stream)
        writer.writerow(CONTEXT_RESULT_COLUMNS)
        writer.writerows(_result_rows(db,count))
        stream.flush()
        os.fsync(stream.fileno())


def _publish_results(db, counts, output, dataset):
    staging = Path(tempfile.mkdtemp(prefix='.aggregate-results-',dir=output))
    try:
        destinations = []
        for count in counts:
            destination = output/f'packet_count_{count}'/'context.csv'
            if destination.resolve().is_relative_to(dataset.resolve()):
                raise ValueError('result publication must be outside the portable dataset')
            temporary = staging/f'packet_count_{count}.csv'
            _write_result_group(db,count,temporary)
            destinations.append((temporary,destination))
        # Every configured CSV has been completely written before any replace.
        for temporary,destination in destinations:
            destination.parent.mkdir(parents=True,exist_ok=True)
            os.replace(temporary,destination)
    finally:
        shutil.rmtree(staging)


def run_aggregate(options: AggregateOptions) -> Path:
    root = Path(options.dataset_root)
    manifest, cohort = _validate_dataset(root)
    output = Path(options.output_root) if options.output_root is not None else Path('results')/manifest['target_chunk']
    if output.resolve().is_relative_to(root.resolve()):
        raise ValueError('output_root must be outside the portable dataset')
    output.mkdir(parents=True,exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.aggregate-',suffix='.sqlite',dir=output)
    os.close(fd)
    database = Path(name)
    try:
        with sqlite3.connect(database) as db:
            _create_tables(db)
            db.executemany('INSERT INTO cohort VALUES ('+','.join('?'*len(_COHORT_RESULT_COLUMNS))+')',
                cohort.loc[:,list(_COHORT_RESULT_COLUMNS)].itertuples(index=False,name=None))
            db.commit()
            _ingest_observations(db,root,manifest['expected_chunk_ids'],cohort)
            _compute_metrics(db)
            _publish_results(db,manifest['packet_counts'],output,root)
    except BaseException as error:
        error.add_note(f'aggregation diagnostic SQLite retained at {database}')
        raise
    finally:
        # Connection's context manager commits/rolls back but does not close.
        if 'db' in locals():
            db.close()
    database.unlink()
    return output


def run_aggregate_cli(args: argparse.Namespace) -> int:
    try:
        run_aggregate(AggregateOptions(Path(args.dataset)))
        return 0
    except Exception as error:
        # Normalize library failures at the CLI boundary; process-control
        # BaseExceptions still propagate, and run_aggregate keeps raising.
        print(f'aggregate failed: {error}',file=sys.stderr)
        for note in getattr(error,'__notes__',()):
            print(note,file=sys.stderr)
        return 1
