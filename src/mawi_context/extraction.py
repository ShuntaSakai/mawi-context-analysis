"""Parent-owned bounded extraction and portable provenance.

Only the parent publishes official chunks, updates progress and deletes raw
captures. Process workers write the unique staging directory in their task.
"""
import argparse
from collections import deque
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
import ipaddress
import os
from pathlib import Path
import shutil
import tempfile

import pandas as pd

from mawi_context.chunks import normalized_day, expected_chunk_ids, validate_target_chunk, render_ditl_chunk_url
from mawi_context.cohort import COHORT_COLUMNS, build_context_indexes, select_target_cohort
from mawi_context.downloader import download_chunk, _owned_source, _paths, _delete_owned_raw
from mawi_context.flow import Endpoint, FLOW_COLUMNS, parse_target_flows
from mawi_context.hashing import sha256_file
from mawi_context.manifests import artifact_record, cohort_identity, load_json_object, write_json_atomically
from mawi_context import observations as obs
from mawi_context.observations import RawSourceIdentity, load_validated_chunk


@dataclass(frozen=True)
class ExtractOptions:
    day: str
    target_chunk: str
    packet_counts: tuple[int, ...]
    workers: int
    dataset_root: Path
    spool_root: Path

    def __post_init__(self):
        object.__setattr__(self, 'day', normalized_day(self.day))
        validate_target_chunk(self.day, self.target_chunk)
        if (not self.packet_counts or any(not isinstance(n, int) or isinstance(n, bool) or n <= 0 for n in self.packet_counts)
                or len(set(self.packet_counts)) != len(self.packet_counts)):
            raise ValueError('packet_counts must contain unique positive integers')
        if not isinstance(self.workers, int) or isinstance(self.workers, bool) or self.workers <= 0:
            raise ValueError('workers must be a positive integer')
        object.__setattr__(self, 'packet_counts', tuple(sorted(self.packet_counts)))
        for name in ('dataset_root', 'spool_root'):
            object.__setattr__(self, name, Path(getattr(self, name)).resolve())


@dataclass(frozen=True)
class ScanChunkTask:
    chunk_id: str
    capture_path: Path
    staging: Path
    dataset_root: Path
    source: RawSourceIdentity
    cohort_identity: str


@dataclass(frozen=True)
class ScanChunkResult:
    chunk_id: str
    staging: Path
    source: RawSourceIdentity
    cohort_identity: str


_worker_indexes = None
_worker_cohort_identity = None


def _read_csv(path: Path, columns: tuple[str, ...]) -> pd.DataFrame:
    # Explicit types avoid nullable SYN ports becoming 80.0 and preserve IPv6.
    strings = {c: 'string' for c in columns if c.endswith('_ip') or c == 'context_source_basis'}
    times = {c: 'float64' for c in columns if c.endswith('_time') or c.endswith('duration')}
    integers = {c: 'Int64' for c in columns if c not in strings and c not in times}
    frame = pd.read_csv(path, dtype={**strings, **times, **integers}, float_precision='round_trip')
    if tuple(frame.columns) != columns:
        raise ValueError('CSV columns mismatch')
    nullable = {c for c in columns if c.startswith('initial_syn_')}
    if frame[[c for c in columns if c not in nullable]].isna().any().any():
        raise ValueError('CSV required fact is null')
    for column in integers:
        if column not in nullable:
            frame[column] = frame[column].astype('int64')
        else:
            frame[column] = pd.Series([None if pd.isna(v) else int(v) for v in frame[column]], dtype=object)
    return frame


def _initialize_scan_worker(cohort_csv: str) -> None:
    global _worker_indexes, _worker_cohort_identity
    cohort = _read_csv(Path(cohort_csv), COHORT_COLUMNS)
    _worker_cohort_identity = cohort_identity(cohort)
    _worker_indexes = build_context_indexes(cohort)


def _scan_chunk_worker(task: ScanChunkTask) -> ScanChunkResult:
    if _worker_indexes is None:
        raise RuntimeError('worker indexes not initialized')
    if task.cohort_identity != _worker_cohort_identity:
        raise ValueError('worker cohort identity mismatch')
    if (task.source.chunk_id != task.chunk_id
            or task.capture_path.stat().st_size != task.source.size_bytes
            or sha256_file(task.capture_path) != task.source.sha256):
        raise ValueError('worker raw identity mismatch')
    counts = obs._write_observations(task.capture_path, _worker_indexes, task.staging)
    manifest = obs._staged_manifest(task.dataset_root, task.staging, task.chunk_id,
                                   task.source, task.cohort_identity, counts)
    write_json_atomically(task.staging/'manifest.json', manifest)
    return ScanChunkResult(task.chunk_id, task.staging, task.source, task.cohort_identity)


def _finish_chunk(task: ScanChunkTask, result: ScanChunkResult, options: ExtractOptions) -> dict:
    if result != ScanChunkResult(task.chunk_id, task.staging, task.source, task.cohort_identity):
        raise ValueError('worker result identity mismatch')
    final = obs._chunk_directory(options.dataset_root, task.chunk_id)
    final.parent.mkdir(parents=True, exist_ok=True)
    state = task.staging.stat(follow_symlinks=False)
    owned_inode = (state.st_dev, state.st_ino)
    try:
        obs._validate_chunk(options.dataset_root, task.staging, task.chunk_id,
                            expected_cohort_identity=task.cohort_identity, expected_source=task.source)
        obs._publish_chunk(task.staging, final)
        manifest = load_validated_chunk(options.dataset_root, task.chunk_id,
                                        expected_cohort_identity=task.cohort_identity)
        if manifest['source'] != asdict(task.source):
            raise ValueError('published source mismatch')
    except BaseException:
        # A signal may occur just after exclusive rename returns in the kernel.
        # Roll back only this parent's staging inode, never another publication.
        try:
            current = final.stat(follow_symlinks=False)
            if (current.st_dev, current.st_ino) == owned_inode:
                obs._publish_chunk(final, task.staging)
        except OSError:
            pass
        raise
    _delete_owned_raw(task.source, options.spool_root)
    return manifest


def _failure(states: dict, chunk: str, phase: str, error: Exception) -> None:
    # Do not serialize exception strings: HTTP, OS and parser errors can carry
    # absolute paths, URLs with credentials, or arbitrary external content.
    previous = states[chunk]
    states[chunk] = dict(status='failed', error={'category': phase, 'message': type(error).__name__})
    if 'source' in previous:
        states[chunk]['source'] = previous['source']


def _schedule_chunks(options, chunk_ids, identity, states, progress, resolver, downloads, scans):
    """Bounded futures: <=2 downloads, <=workers scans, <=workers+2 active raw.

    Failed raw captures are deliberately retained and are outside the active
    spool bound. No failed scan is submitted again in this run.
    Executors are injected so scheduling can be exercised without processes.
    """
    pending = deque(chunk_ids)
    ready = deque()
    downloading, scanning = {}, {}
    parent = options.dataset_root/'observations'
    if parent.is_symlink():
        raise ValueError('observations directory must not be a symlink')
    parent.mkdir(parents=True, exist_ok=True)
    while pending or ready or downloading or scanning:
        while ready and len(scanning) < options.workers:
            source = ready.popleft()
            stage = None
            try:
                stage = Path(tempfile.mkdtemp(prefix=f'.staging-{source.chunk_id}-', dir=parent))
                task = ScanChunkTask(source.chunk_id, _paths(source.chunk_id, options.spool_root)[0],
                                     stage, options.dataset_root, source, identity)
                scanning[scans.submit(_scan_chunk_worker, task)] = task
            except Exception as error:
                if stage is not None:
                    shutil.rmtree(stage, ignore_errors=True)
                _failure(states, source.chunk_id, 'scan', error)
                progress()
        while (pending and len(downloading) < 2
               and len(downloading)+len(scanning)+len(ready) < options.workers+2):
            chunk = pending.popleft()
            try:
                url = resolver(options.day, chunk)
                if os.path.lexists(parent/chunk):
                    manifest = load_validated_chunk(options.dataset_root, chunk, expected_cohort_identity=identity)
                    source = RawSourceIdentity(**manifest['source'])
                    owned = (_owned_source(chunk, url, options.spool_root)
                             if os.path.lexists(_paths(chunk, options.spool_root)[0]) else None)
                    if source.source_url != url or (owned is not None and owned != source):
                        raise ValueError('cached source identity mismatch')
                    if 'source' in states[chunk] and states[chunk]['source'] != asdict(source):
                        raise ValueError('prior source identity mismatch')
                    if owned is not None:
                        _delete_owned_raw(owned, options.spool_root)
                    states[chunk] = dict(status='success', source=asdict(source), manifest=f'observations/{chunk}/manifest.json')
                    progress()
                    continue
                owned = _owned_source(chunk, url, options.spool_root)
                if owned is not None:
                    if 'source' in states[chunk] and states[chunk]['source'] != asdict(owned):
                        raise ValueError('prior raw source identity mismatch')
                    states[chunk]['source'] = asdict(owned)
                    ready.append(owned)
                else:
                    downloading[downloads.submit(download_chunk, chunk, url, options.spool_root)] = chunk
            except Exception as error:
                _failure(states, chunk, 'acquisition-or-cache', error)
                progress()
        # Start ready work before blocking, even while later downloads run.
        if ready and len(scanning) < options.workers:
            continue
        futures = set(downloading) | set(scanning)
        if not futures:
            continue
        done, _ = wait(futures, return_when=FIRST_COMPLETED)
        for future in done:
            if future in downloading:
                chunk = downloading.pop(future)
                try:
                    source = RawSourceIdentity(**future.result())
                    if source.chunk_id != chunk or source.source_url != resolver(options.day, chunk):
                        raise ValueError('download result identity mismatch')
                    if 'source' in states[chunk] and states[chunk]['source'] != asdict(source):
                        raise ValueError('prior download source identity mismatch')
                    states[chunk]['source'] = asdict(source)
                    ready.append(source)
                except Exception as error:
                    _failure(states, chunk, 'download', error)
            else:
                task = scanning.pop(future)
                try:
                    manifest = _finish_chunk(task, future.result(), options)
                    states[task.chunk_id] = dict(status='success', source=manifest['source'],
                                                manifest=f'observations/{task.chunk_id}/manifest.json')
                except Exception as error:
                    _failure(states, task.chunk_id, 'scan-or-publication', error)
                finally:
                    shutil.rmtree(task.staging, ignore_errors=True)
            progress()


FLOW_DEFINITION = {
    'protocols': [6, 17], 'key': 'direction-independent-bidirectional-5-tuple',
    'inactivity_timeout': None, 'src_dst': 'first-observed-packet-direction',
}
CONTEXT_SOURCE_POLICY = {
    'tcp': 'initial-plain-syn-sender-else-first-observed-src',
    'udp': 'first-observed-src',
}
TOOL_IDENTITY = {'name': 'mawi-context-analysis', 'version': '0.1.0', 'extraction': 'v1'}


def _flow_manifest(options, source, record):
    return dict(manifest_schema_version='flow-manifest-v1', status='success',
                target_chunk=options.target_chunk, source=asdict(source),
                flow_definition=FLOW_DEFINITION, tool=TOOL_IDENTITY, artifact=record)


def _cohort_manifest(options, source, identity, record):
    return dict(manifest_schema_version='cohort-manifest-v1', status='success',
                target_chunk=options.target_chunk, source=asdict(source),
                packet_counts=list(options.packet_counts), context_source_policy=CONTEXT_SOURCE_POLICY,
                cohort_identity=identity, tool=TOOL_IDENTITY, artifact=record)


def _validated_csv(root, relative, columns, version, record):
    if (not isinstance(record, dict) or not isinstance(record.get('row_count'), int)
            or isinstance(record['row_count'], bool) or record['row_count'] < 0):
        raise ValueError('CSV artifact row_count must be a nonnegative integer')
    frame = _read_csv(root/relative, columns)
    expected = artifact_record(root, root/relative, row_count=len(frame), schema_version=version)
    if record != expected:
        raise ValueError('CSV artifact identity mismatch')
    return frame


def _validate_flow_identifiers(flows):
    if flows.empty:
        return
    if (flows.flow_id.le(0).any() or flows.flow_id.duplicated().any()
            or flows.packet_count.le(0).any()):
        raise ValueError('invalid full flow IDs/counts')
    for row in flows.itertuples(index=False):
        for direction in ('src', 'dst'):
            endpoint = Endpoint(getattr(row, direction+'_ip'), getattr(row, direction+'_port'))
            if ipaddress.ip_address(endpoint.ip).version != row.ip_version:
                raise ValueError('flow IP version mismatch')
        for role in ('sender', 'receiver'):
            ip = getattr(row, 'initial_syn_'+role+'_ip')
            port = getattr(row, 'initial_syn_'+role+'_port')
            if pd.isna(ip) != pd.isna(port):
                raise ValueError('partial SYN endpoint')
            if not pd.isna(ip):
                Endpoint(ip, port)
    counts = tuple(sorted(set(flows.packet_count)))
    all_flows = select_target_cohort(flows, counts)
    cohort_identity(all_flows)
    build_context_indexes(all_flows)


def _target_provenance(options, resolver, expected_source=None):
    root = options.dataset_root
    flow_dir, cohort_dir = root/'provenance', root/'cohort'
    if os.path.lexists(flow_dir) or os.path.lexists(cohort_dir):
        if (flow_dir.is_symlink() or cohort_dir.is_symlink()
                or not flow_dir.is_dir() or not cohort_dir.is_dir()
                or {p.name for p in flow_dir.iterdir()} != {'flows.csv', 'flow_manifest.json'}
                or {p.name for p in cohort_dir.iterdir()} != {'target_cohort.csv', 'cohort_manifest.json'}
                or any(p.is_symlink() or not p.is_file() for d in (flow_dir,cohort_dir) for p in d.iterdir())):
            raise ValueError('incomplete or malformed target provenance')
        fm = load_json_object(flow_dir/'flow_manifest.json')
        cm = load_json_object(cohort_dir/'cohort_manifest.json')
        try:
            source = RawSourceIdentity(**fm['source'])
            flows = _validated_csv(root, 'provenance/flows.csv', FLOW_COLUMNS, 'flows-v1', fm['artifact'])
            cohort = _validated_csv(root, 'cohort/target_cohort.csv', COHORT_COLUMNS, 'cohort-v1', cm['artifact'])
            _validate_flow_identifiers(flows)
            if not isinstance(cm.get('packet_counts'), list) or any(type(n) is not int for n in cm['packet_counts']):
                raise ValueError('invalid cohort packet counts')
            identity = cohort_identity(cohort)
            if expected_source is not None and asdict(source) != expected_source:
                raise ValueError('target provenance/prior source mismatch')
            if (fm != _flow_manifest(options, source, fm['artifact'])
                    or cm != _cohort_manifest(options, source, identity, cm['artifact'])
                    or source.chunk_id != options.target_chunk
                    or source.source_url != resolver(options.day, options.target_chunk)):
                raise ValueError('target provenance identity mismatch')
            expected = select_target_cohort(flows, options.packet_counts).reset_index(drop=True)
            pd.testing.assert_frame_equal(cohort, expected, check_dtype=False, check_exact=True)
            build_context_indexes(cohort)
        except (KeyError, TypeError, AssertionError) as error:
            raise ValueError('invalid target provenance') from error
        return source, identity

    source = RawSourceIdentity(**download_chunk(options.target_chunk,
                                resolver(options.day, options.target_chunk), options.spool_root))
    if expected_source is not None and asdict(source) != expected_source:
        raise ValueError('target acquisition/prior source mismatch')
    flows = parse_target_flows(_paths(options.target_chunk, options.spool_root)[0]).frame
    root.mkdir(parents=True, exist_ok=True)
    flow_stage = Path(tempfile.mkdtemp(prefix='.provenance-', dir=root))
    cohort_stage = Path(tempfile.mkdtemp(prefix='.cohort-', dir=root))
    staging_inodes = {}
    for stage, final in ((flow_stage, flow_dir), (cohort_stage, cohort_dir)):
        stat = stage.stat(follow_symlinks=False)
        staging_inodes[final] = (stat.st_dev, stat.st_ino)
    try:
        flows.to_csv(flow_stage/'flows.csv', index=False)
        flows = _read_csv(flow_stage/'flows.csv', FLOW_COLUMNS)
        _validate_flow_identifiers(flows)
        cohort = select_target_cohort(flows, options.packet_counts)
        cohort.to_csv(cohort_stage/'target_cohort.csv', index=False)
        cohort = _read_csv(cohort_stage/'target_cohort.csv', COHORT_COLUMNS)
        identity = cohort_identity(cohort)
        build_context_indexes(cohort)
        record = artifact_record(root, flow_stage/'flows.csv', row_count=len(flows), schema_version='flows-v1')
        record['path'] = 'provenance/flows.csv'
        write_json_atomically(flow_stage/'flow_manifest.json', _flow_manifest(options, source, record))
        record = artifact_record(root, cohort_stage/'target_cohort.csv', row_count=len(cohort), schema_version='cohort-v1')
        record['path'] = 'cohort/target_cohort.csv'
        write_json_atomically(cohort_stage/'cohort_manifest.json', _cohort_manifest(options, source, identity, record))
        obs._publish_chunk(flow_stage, flow_dir)
        obs._publish_chunk(cohort_stage, cohort_dir)
    except BaseException:
        for stage, final in ((flow_stage, flow_dir), (cohort_stage, cohort_dir)):
            try:
                stat = final.stat(follow_symlinks=False)
                if (stat.st_dev, stat.st_ino) == staging_inodes[final]:
                    obs._publish_chunk(final, stage)
            except OSError:
                pass
        raise
    finally:
        shutil.rmtree(flow_stage, ignore_errors=True)
        shutil.rmtree(cohort_stage, ignore_errors=True)
    return source, identity


def _dataset_header(options, chunk_ids, identity):
    return dict(manifest_schema_version='dataset-manifest-v1', day=options.day,
                target_chunk=options.target_chunk, packet_counts=list(options.packet_counts),
                cohort_identity=identity, expected_chunk_ids=list(chunk_ids),
                flow_manifest='provenance/flow_manifest.json', cohort_manifest='cohort/cohort_manifest.json',
                observation_schemas={'target_packets': obs.TARGET_PACKET_SCHEMA_VERSION,
                                     'source_context_packets': obs.SOURCE_CONTEXT_SCHEMA_VERSION,
                                     'chunk_manifest': obs.CHUNK_MANIFEST_SCHEMA_VERSION}, tool=TOOL_IDENTITY)


def _validate_dataset_state(value, header):
    identity = value.get('cohort_identity')
    if identity is not None:
        obs._validate_digest(identity)
    counts = value.get('packet_counts')
    if not isinstance(counts, list) or any(type(n) is not int or n <= 0 for n in counts):
        raise ValueError('invalid dataset packet counts')
    if set(value) != set(header) | {'status', 'chunks'} or any(value[k] != v for k,v in header.items()):
        raise ValueError('dataset identity mismatch')
    if value['status'] not in ('incomplete', 'success') or not isinstance(value['chunks'], dict) or set(value['chunks']) != set(header['expected_chunk_ids']):
        raise ValueError('invalid dataset state')
    for chunk, state in value['chunks'].items():
        if not isinstance(state, dict) or state.get('status') not in ('pending','success','failed'):
            raise ValueError('invalid chunk progress')
        allowed = {'status','source','manifest','error'}
        if not set(state) <= allowed:
            raise ValueError('invalid chunk progress structure')
        if 'source' in state:
            try:
                source = RawSourceIdentity(**state['source'])
            except (TypeError, ValueError) as error:
                raise ValueError('invalid progress source') from error
            if source.chunk_id != chunk:
                raise ValueError('progress source mismatch')
        if state['status']=='success' and ('source' not in state or state.get('manifest') != f'observations/{chunk}/manifest.json'):
            raise ValueError('invalid success state')
        if state['status']=='failed' and (not isinstance(state.get('error'),dict) or set(state['error']) != {'category','message'}):
            raise ValueError('invalid failure state')
    if identity is None:
        states = value['chunks']
        target = header['target_chunk']
        if (value['status'] != 'incomplete' or states[target].get('status') != 'failed'
                or states[target].get('error', {}).get('category') != 'target-provenance'
                or any(states[c].get('status') != 'pending' for c in states if c != target)):
            raise ValueError('null cohort identity only allowed before target provenance')
    if value['status']=='success' and any(s['status']!='success' for s in value['chunks'].values()):
        raise ValueError('inconsistent dataset success')


class IncompleteExtractionError(RuntimeError):
    """Independent work finished; inspect dataset_manifest.json for failures."""


def run_extract(
    options: ExtractOptions, *,
    source_url_resolver: Callable[[str, str], str] = render_ditl_chunk_url,
) -> Path:
    """Target first, then bounded independent scans; reruns validate and reuse."""
    ids = expected_chunk_ids(options.day)
    path = options.dataset_root/'dataset_manifest.json'
    observations = options.dataset_root/'observations'
    if observations.is_symlink() or (os.path.lexists(observations) and not observations.is_dir()):
        raise ValueError('observations directory must be a regular directory')
    if path.is_symlink():
        raise ValueError('dataset manifest must not be a symlink')
    # Validate existing top-level identity before acquisition or publication.
    previous = load_json_object(path) if os.path.lexists(path) else None
    if previous is not None:
        _validate_dataset_state(previous, _dataset_header(options, ids, previous.get('cohort_identity')))
    provenance_existed = any(os.path.lexists(options.dataset_root/name) for name in ('provenance','cohort'))
    prior_target = previous['chunks'][options.target_chunk].get('source') if previous is not None else None
    try:
        source, identity = _target_provenance(options, source_url_resolver, prior_target)
    except Exception as error:
        if provenance_existed:
            raise
        states = {c:dict(status='pending') for c in ids}
        if prior_target is not None:
            states[options.target_chunk]['source'] = prior_target
        _failure(states, options.target_chunk, 'target-provenance', error)
        try:
            owned = _owned_source(options.target_chunk, source_url_resolver(options.day, options.target_chunk), options.spool_root)
            if owned is not None and (prior_target is None or asdict(owned) == prior_target):
                states[options.target_chunk]['source'] = asdict(owned)
        except (ValueError, OSError):
            pass
        write_json_atomically(path, dict(_dataset_header(options, ids, None), status='incomplete', chunks=states))
        raise IncompleteExtractionError('target acquisition/provenance failed') from error
    header = _dataset_header(options, ids, identity)
    if previous is not None and previous['cohort_identity'] is not None:
        _validate_dataset_state(previous, header)
        prior_target = previous['chunks'][options.target_chunk].get('source')
        if prior_target is not None and prior_target != asdict(source):
            raise ValueError('target provenance/prior source mismatch')
    states = {c:dict(status='pending', **({'source':previous['chunks'][c]['source']}
              if previous is not None and 'source' in previous['chunks'][c] else {})) for c in ids}
    states[options.target_chunk]['source'] = asdict(source)
    def progress():
        status = 'success' if all(s['status']=='success' for s in states.values()) else 'incomplete'
        write_json_atomically(path, dict(header, status=status, chunks=states))
    progress()
    with ThreadPoolExecutor(max_workers=2) as downloads:
        with ProcessPoolExecutor(max_workers=options.workers, initializer=_initialize_scan_worker,
                                 initargs=(str(options.dataset_root/'cohort/target_cohort.csv'),)) as scans:
            _schedule_chunks(options, ids, identity, states, progress, source_url_resolver, downloads, scans)
    progress()
    if any(s['status'] != 'success' for s in states.values()):
        raise IncompleteExtractionError('extraction incomplete; inspect dataset_manifest.json')
    return options.dataset_root


def run_extract_cli(args: argparse.Namespace) -> int:
    import sys
    try:
        # The public CLI intentionally exposes no acquisition tuning options.
        base = Path('data')/validate_target_chunk(args.day, args.target_chunk)
        options = ExtractOptions(args.day, args.target_chunk, tuple(args.packet_counts),
                                 args.workers, base/'portable_dataset', base/'spool')
        dataset_root = run_extract(options)
        return 0 if load_json_object(dataset_root/'dataset_manifest.json')['status']=='success' else 1
    except (ValueError, OSError, IncompleteExtractionError) as error:
        print(f'extract failed: {error}', file=sys.stderr)
        return 1
