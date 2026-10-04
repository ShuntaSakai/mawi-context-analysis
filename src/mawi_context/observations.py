"""Bounded, observational packet caches for one capture chunk.

Task 2's private decoder and skip exception are deliberately shared here:
there is one packet decoder and no change to its research semantics.
"""
from dataclasses import asdict, dataclass
import ctypes
import errno
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import sys
import tempfile

import pyarrow as pa
import pyarrow.parquet as pq

from mawi_context.capture import iter_capture_records
from mawi_context.cohort import ContextIndexes
from mawi_context.flow import FlowKey, _decode, _SkipPacket
from mawi_context.hashing import sha256_file
from mawi_context.manifests import (
    artifact_record, load_json_object, resolve_artifact_path, write_json_atomically,
)


TARGET_PACKET_SCHEMA_VERSION = 'target-packets-v1'
SOURCE_CONTEXT_SCHEMA_VERSION = 'source-context-packets-v1'
CHUNK_MANIFEST_SCHEMA_VERSION = 'chunk-manifest-v1'
_ROW_BUFFER_LIMIT = 4096

SOURCE_CONTEXT_SCHEMA = pa.schema([
    pa.field('packet_index', pa.int64(), nullable=False),
    pa.field('timestamp', pa.float64(), nullable=False),
    pa.field('ip_version', pa.uint8(), nullable=False),
    pa.field('protocol', pa.uint8(), nullable=False),
    pa.field('src_ip', pa.string(), nullable=False),
    pa.field('src_port', pa.uint16(), nullable=False),
    pa.field('dst_ip', pa.string(), nullable=False),
    pa.field('dst_port', pa.uint16(), nullable=False),
    pa.field('captured_frame_length', pa.uint32(), nullable=False),
    pa.field('original_frame_length', pa.uint32(), nullable=False),
    pa.field('ip_total_length', pa.uint32(), nullable=False),
    pa.field('transport_payload_length', pa.uint32(), nullable=False),
    pa.field('tcp_flags_raw', pa.uint8(), nullable=True),
])
TARGET_PACKET_SCHEMA = pa.schema([
    pa.field('target_flow_id', pa.int64(), nullable=False),
    *SOURCE_CONTEXT_SCHEMA,
])


def _flush(writer: pq.ParquetWriter, rows: list[dict], schema: pa.Schema) -> None:
    if rows:
        writer.write_table(pa.Table.from_pylist(rows, schema=schema))
        rows.clear()


def _write_observations(
    capture_path: Path, indexes: ContextIndexes, staging: Path,
) -> tuple[int, int]:
    """Write only to owned staging; return logical counts after writer close."""
    target_rows, source_rows = [], []
    target_count = source_count = 0
    with pq.ParquetWriter(staging/'target_packets.parquet', TARGET_PACKET_SCHEMA) as target_writer:
        with pq.ParquetWriter(staging/'source_context_packets.parquet', SOURCE_CONTEXT_SCHEMA) as source_writer:
            for record in iter_capture_records(capture_path):
                try:
                    facts = _decode(record)
                except _SkipPacket:
                    continue
                key = FlowKey.from_packet(facts.src_ip, facts.src_port, facts.dst_ip,
                                          facts.dst_port, facts.protocol)
                target_id = indexes.target_flow_by_key.get(key)
                candidate = indexes.candidate_source_ips
                retain_source = (
                    bool(facts.tcp_flags & 0x07)
                    and (facts.src_ip in candidate or facts.dst_ip in candidate)
                    if facts.protocol == 6 else facts.src_ip in candidate
                )
                if target_id is None and not retain_source:
                    continue
                row = dict(
                    packet_index=record.packet_index, timestamp=record.timestamp,
                    ip_version=facts.ip_version, protocol=facts.protocol,
                    src_ip=facts.src_ip, src_port=facts.src_port,
                    dst_ip=facts.dst_ip, dst_port=facts.dst_port,
                    captured_frame_length=record.captured_length,
                    original_frame_length=record.original_length,
                    ip_total_length=facts.ip_total_length,
                    transport_payload_length=facts.transport_payload_length,
                    tcp_flags_raw=facts.tcp_flags if facts.protocol == 6 else None,
                )
                if target_id is not None:
                    target_rows.append(dict(target_flow_id=target_id, **row))
                    target_count += 1
                    if len(target_rows) >= _ROW_BUFFER_LIMIT:
                        _flush(target_writer, target_rows, TARGET_PACKET_SCHEMA)
                if retain_source:
                    source_rows.append(row)
                    source_count += 1
                    if len(source_rows) >= _ROW_BUFFER_LIMIT:
                        _flush(source_writer, source_rows, SOURCE_CONTEXT_SCHEMA)
            _flush(target_writer, target_rows, TARGET_PACKET_SCHEMA)
            _flush(source_writer, source_rows, SOURCE_CONTEXT_SCHEMA)
    return target_count, source_count


def _validate_chunk_id(value: str) -> None:
    if (not isinstance(value, str) or not value.strip() or value in ('.', '..')
            or any(c in value for c in ('/', '\\', '\x00'))
            or PureWindowsPath(value).drive):
        raise ValueError('chunk_id must be a safe nonempty directory component')


def _validate_digest(value: str) -> None:
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('identity must be a lowercase SHA-256 hex digest')


@dataclass(frozen=True)
class RawSourceIdentity:
    """Identity of the actual raw file bytes, including compressed containers."""

    chunk_id: str
    source_url: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        _validate_chunk_id(self.chunk_id)
        if not isinstance(self.source_url, str) or not self.source_url.strip():
            raise ValueError('source_url must be a nonempty string')
        _validate_digest(self.sha256)
        if (not isinstance(self.size_bytes, int) or isinstance(self.size_bytes, bool)
                or self.size_bytes < 0):
            raise ValueError('size_bytes must be a nonnegative integer')


def _chunk_directory(dataset_root: Path, chunk_id: str) -> Path:
    _validate_chunk_id(chunk_id)
    relative = f'observations/{chunk_id}'
    resolve_artifact_path(dataset_root, relative)
    directory = dataset_root/'observations'/chunk_id
    if directory.parent.is_symlink() or directory.is_symlink():
        raise ValueError('chunk directories must not be symlinks')
    return directory


def _require_keys(value: object, keys: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f'invalid {label} structure')


def _validate_chunk(
    dataset_root: Path, directory: Path, chunk_id: str, *,
    expected_cohort_identity: str,
    expected_source: RawSourceIdentity | None = None,
) -> dict[str, object]:
    """Independently reload staging or final, whose manifest names final paths.

    Each Parquet is fully read in bounded batches: a readable footer alone
    does not prove the data pages or their actual row count are readable.
    """
    _validate_chunk_id(chunk_id)
    _validate_digest(expected_cohort_identity)
    names = {'manifest.json', 'target_packets.parquet', 'source_context_packets.parquet'}
    if (directory.is_symlink() or not directory.is_dir()
            or {p.name for p in directory.iterdir()} != names
            or any((directory/name).is_symlink() or not (directory/name).is_file()
                   for name in names)):
        raise ValueError('chunk directory must contain exactly three regular files')
    manifest = load_json_object(directory/'manifest.json')
    _require_keys(manifest, {
        'manifest_schema_version', 'status', 'chunk_id', 'cohort_identity', 'source', 'artifacts',
    }, 'chunk manifest')
    if (manifest['manifest_schema_version'] != CHUNK_MANIFEST_SCHEMA_VERSION
            or manifest['status'] != 'success' or manifest['chunk_id'] != chunk_id
            or manifest['cohort_identity'] != expected_cohort_identity):
        raise ValueError('chunk version/status/identity mismatch')
    _require_keys(manifest['source'], {'chunk_id', 'source_url', 'sha256', 'size_bytes'}, 'raw source')
    source = RawSourceIdentity(**manifest['source'])
    if source.chunk_id != chunk_id or (expected_source is not None and source != expected_source):
        raise ValueError('raw source identity mismatch')
    _require_keys(manifest['artifacts'], {'target_packets', 'source_context_packets'}, 'artifacts')
    for name, schema, version in (
        ('target_packets', TARGET_PACKET_SCHEMA, TARGET_PACKET_SCHEMA_VERSION),
        ('source_context_packets', SOURCE_CONTEXT_SCHEMA, SOURCE_CONTEXT_SCHEMA_VERSION),
    ):
        record = manifest['artifacts'][name]
        _require_keys(record, {'path', 'sha256', 'row_count', 'schema_version'}, 'artifact')
        relative = f'observations/{chunk_id}/{name}.parquet'
        if record['path'] != relative or record['schema_version'] != version:
            raise ValueError('artifact path/schema version mismatch')
        resolve_artifact_path(dataset_root, record['path'])
        _validate_digest(record['sha256'])
        count = record['row_count']
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError('artifact row_count must be a nonnegative integer')
        path = directory/f'{name}.parquet'
        if sha256_file(path) != record['sha256']:
            raise ValueError('artifact checksum mismatch')
        with pq.ParquetFile(path) as parquet:
            if not parquet.schema_arrow.equals(schema, check_metadata=True):
                raise ValueError('artifact schema mismatch')
            actual = 0
            for batch in parquet.iter_batches(batch_size=_ROW_BUFFER_LIMIT):
                actual += batch.num_rows
                for field, column in zip(schema, batch.columns):
                    if not field.nullable and column.null_count:
                        raise ValueError('null in non-nullable observation field')
            if actual != count or parquet.metadata.num_rows != count:
                raise ValueError('artifact row count mismatch')
    return manifest


def load_validated_chunk(
    dataset_root: Path, chunk_id: str, *, expected_cohort_identity: str,
) -> dict[str, object]:
    """Validate portable cache facts from disk, without requiring the raw file."""
    _validate_digest(expected_cohort_identity)
    directory = _chunk_directory(dataset_root, chunk_id)
    return _validate_chunk(dataset_root, directory, chunk_id,
                           expected_cohort_identity=expected_cohort_identity)


def _publish_chunk(staging: Path, destination: Path) -> None:
    """Atomic directory rename with no replacement, including an empty final.

    Plain POSIX rename may replace an empty directory after an existence-check
    race. Use the OS exclusive-rename primitive on the laboratory Linux and
    development macOS platforms. Fail safely on unsupported platforms.
    """
    if os.path.lexists(destination):
        raise FileExistsError(errno.EEXIST, 'chunk already exists', str(destination))
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == 'darwin':
        rename = library.renamex_np
        rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        args = (os.fsencode(staging), os.fsencode(destination), 0x04)  # RENAME_EXCL
    elif sys.platform.startswith('linux') and hasattr(library, 'renameat2'):
        rename = library.renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        args = (-100, os.fsencode(staging), -100, os.fsencode(destination), 1)  # NOREPLACE
    else:
        raise OSError('atomic exclusive directory publication is unsupported on this platform')
    rename.restype = ctypes.c_int
    if rename(*args) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(destination))


def _staged_manifest(
    dataset_root: Path, staging: Path, chunk_id: str, source: RawSourceIdentity,
    cohort_identity_value: str, counts: tuple[int, int],
) -> dict[str, object]:
    artifacts = {}
    for name, count, version in (
        ('target_packets', counts[0], TARGET_PACKET_SCHEMA_VERSION),
        ('source_context_packets', counts[1], SOURCE_CONTEXT_SCHEMA_VERSION),
    ):
        record = artifact_record(dataset_root, staging/f'{name}.parquet',
                                 row_count=count, schema_version=version)
        # Hash closed staging bytes through Task 4, but persist only the final
        # portable path. Staging's random name must never enter cache identity.
        record['path'] = f'observations/{chunk_id}/{name}.parquet'
        artifacts[name] = record
    return dict(manifest_schema_version=CHUNK_MANIFEST_SCHEMA_VERSION,
                status='success', chunk_id=chunk_id, cohort_identity=cohort_identity_value,
                source=asdict(source), artifacts=artifacts)


def extract_chunk_observations(
    capture_path: Path, indexes: ContextIndexes, dataset_root: Path,
    chunk_id: str, source: RawSourceIdentity, *, cohort_identity_value: str,
) -> dict[str, object]:
    """Verify raw identity, stage, validate, publish, then reload the final cache.

    Compatible immutable caches are reused. Cleanup owns only this call's
    staging and, if final reload fails, this call's new publication. No raw
    captures or preexisting final artifacts are ever deleted or replaced.
    """
    final = _chunk_directory(dataset_root, chunk_id)
    _validate_digest(cohort_identity_value)
    if not isinstance(source, RawSourceIdentity) or source.chunk_id != chunk_id:
        raise ValueError('raw source chunk_id mismatch')
    if (capture_path.stat().st_size != source.size_bytes
            or sha256_file(capture_path) != source.sha256):
        raise ValueError('raw capture size/SHA-256 mismatch')
    if os.path.lexists(final):
        manifest = load_validated_chunk(dataset_root, chunk_id,
                                        expected_cohort_identity=cohort_identity_value)
        if manifest['source'] != asdict(source):
            raise ValueError('existing cache raw source identity mismatch')
        return manifest
    final.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f'.staging-{chunk_id}-', dir=final.parent))
    staging_identity = None
    try:
        state = staging.stat(follow_symlinks=False)
        staging_identity = (state.st_dev, state.st_ino)
        counts = _write_observations(capture_path, indexes, staging)
        manifest = _staged_manifest(dataset_root, staging, chunk_id, source,
                                    cohort_identity_value, counts)
        write_json_atomically(staging/'manifest.json', manifest)
        _validate_chunk(dataset_root, staging, chunk_id,
                        expected_cohort_identity=cohort_identity_value, expected_source=source)
        _publish_chunk(staging, final)
        return load_validated_chunk(dataset_root, chunk_id,
                                     expected_cohort_identity=cohort_identity_value)
    except BaseException:
        # A signal can arrive after the OS rename but before Python returns
        # from publication. Identify our directory on disk instead of relying
        # on a success flag; never roll back another caller's final directory.
        try:
            state = final.stat(follow_symlinks=False)
            if (state.st_dev, state.st_ino) == staging_identity:
                _publish_chunk(final, staging)
        except OSError:
            pass  # Preserve the original failure if rollback cannot run.
        raise
    finally:
        try:
            shutil.rmtree(staging)
        except OSError:
            pass  # Best effort cleanup must not mask the original exception.
