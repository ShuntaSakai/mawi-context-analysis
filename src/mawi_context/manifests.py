"""Portable artifact records and small provenance validation primitives.

These helpers do not define dataset or chunk manifest schemas, publication,
resume, or deletion policy. Absolute paths are used only for local validation.
"""
from collections.abc import Mapping
import ipaddress
import json
from numbers import Integral
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import tempfile

import pandas as pd

from mawi_context.cohort import build_context_indexes
from mawi_context.flow import FlowKey
from mawi_context.hashing import sha256_file, stable_json_hash


_IDENTITY_COLUMNS = (
    'target_flow_id', 'protocol', 'src_ip', 'src_port',
    'dst_ip', 'dst_port', 'context_source_ip',
)


def write_json_atomically(path: Path, value: Mapping[str, object]) -> None:
    """Create parents and replace an object only after serialization and fsync.

    UTF-8 JSON is human-readable. The temporary file resides beside the target;
    serialization or pre-replacement I/O failure leaves the target untouched.
    This syncs the file, not the directory entry after replacement.
    """
    if not isinstance(value, Mapping):
        raise TypeError('manifest root must be a mapping')
    content = json.dumps(dict(value), ensure_ascii=False, allow_nan=False, indent=2) + '\n'
    # Encode before creating anything, also rejecting invalid UTF-8 strings.
    encoded = content.encode('utf-8')
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='wb', dir=path.parent, prefix=f'.{path.name}.', suffix='.tmp',
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                # Best effort: a cleanup error must not hide the original failure.
                pass


def _reject_json_constant(value: str) -> object:
    raise ValueError(f'non-standard JSON constant: {value}')


def load_json_object(path: Path) -> dict[str, object]:
    """Load strict UTF-8 JSON, requiring an object root (no NaN/Infinity)."""
    with path.open('r', encoding='utf-8') as stream:
        value = json.load(stream, parse_constant=_reject_json_constant)
    if not isinstance(value, dict):
        raise ValueError('manifest root must be a JSON object')
    return value


def _integer_fact(value: object, column: str, minimum: int) -> int:
    if not isinstance(value, Integral) or isinstance(value, bool) or value < minimum:
        raise ValueError(f'{column} must be an integer >= {minimum}')
    return int(value)


def _ip_fact(value: object, column: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f'{column} must be an IP address string')
    try:
        ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError(f'{column} must be a valid IP address') from error
    return value


def cohort_identity(cohort: pd.DataFrame) -> str:
    """Hash retention facts sorted by ID, canonical FlowKey, and source text.

    Each row contributes target_flow_id, protocol, the bidirectional endpoint
    IP/port pairs from FlowKey, and context_source_ip. Index, column/row order,
    time/count/basis metadata, and first-observed tuple direction do not enter
    this retention identity. They remain provenance in the unchanged cohort.
    Duplicate rows retain multiplicity. Conflicting ID/FlowKey lookups fail.

    Endpoint IPs are normalized by FlowKey. Context source IPs are validated
    but retain their spelling: Task 3's candidate_source_ips uses exact string
    membership, so normalizing that string here would mask a lookup change.
    """
    missing = [column for column in _IDENTITY_COLUMNS if column not in cohort.columns]
    if missing:
        raise ValueError(f'missing required columns: {", ".join(missing)}')
    if any(list(cohort.columns).count(column) != 1 for column in _IDENTITY_COLUMNS):
        raise ValueError('duplicate identity columns')
    validated = []
    facts = []
    for row in cohort.loc[:, list(_IDENTITY_COLUMNS)].itertuples(index=False, name=None):
        values = dict(zip(_IDENTITY_COLUMNS, row))
        for column in ('target_flow_id', 'protocol', 'src_port', 'dst_port'):
            values[column] = _integer_fact(
                values[column], column, 1 if column == 'target_flow_id' else 0,
            )
        for column in ('src_ip', 'dst_ip', 'context_source_ip'):
            values[column] = _ip_fact(values[column], column)
        key = FlowKey.from_packet(
            values['src_ip'], values['src_port'], values['dst_ip'],
            values['dst_port'], values['protocol'],
        )
        validated.append(values)
        facts.append((
            values['target_flow_id'], key.protocol,
            key.endpoint_a.ip, key.endpoint_a.port,
            key.endpoint_b.ip, key.endpoint_b.port, values['context_source_ip'],
        ))
    # Reuse Task 3's conflict contract after converting numpy scalars to ints.
    build_context_indexes(pd.DataFrame(validated, columns=_IDENTITY_COLUMNS))
    return stable_json_hash(sorted(facts))


def resolve_artifact_path(dataset_root: Path, relative_path: str) -> Path:
    """Resolve a canonical POSIX relative file path, checking symlink escapes.

    Reject empty paths, absolute/Windows paths, backslashes, parent/dot
    components, and redundant separators. A not-yet-existing file is allowed,
    but any existing ancestor symlink must resolve inside the dataset root.
    """
    if not isinstance(relative_path, str) or not relative_path or '\x00' in relative_path:
        raise ValueError('artifact path must be a nonempty POSIX relative path')
    posix = PurePosixPath(relative_path)
    if (posix.is_absolute() or '\\' in relative_path
            or PureWindowsPath(relative_path).drive
            or any(part in ('', '.', '..') for part in relative_path.split('/'))):
        raise ValueError('artifact path must be a canonical POSIX relative path')
    root = dataset_root.resolve()
    resolved = root.joinpath(*posix.parts).resolve()
    if not resolved.is_relative_to(root):
        raise ValueError('artifact path escapes dataset root')
    return resolved


def artifact_record(
    dataset_root: Path, artifact_path: Path, *, row_count: int, schema_version: str,
) -> dict[str, object]:
    """Record only path, sha256, row_count, schema_version; no local root."""
    count = _integer_fact(row_count, 'row_count', 0)
    if not isinstance(schema_version, str) or not schema_version.strip():
        raise ValueError('schema_version must be a nonempty string')
    try:
        relative = artifact_path.absolute().relative_to(dataset_root.absolute()).as_posix()
    except ValueError as error:
        raise ValueError('artifact path is outside dataset root') from error
    resolved = resolve_artifact_path(dataset_root, relative)
    return {
        'path': relative,
        'sha256': sha256_file(resolved),
        'row_count': count,
        'schema_version': schema_version,
    }
