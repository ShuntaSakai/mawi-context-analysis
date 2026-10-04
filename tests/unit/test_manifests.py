"""Portable primitive contracts; all artifacts and cohorts are synthetic."""
import hashlib
import json
from pathlib import Path
import shutil
from types import MappingProxyType

import numpy as np
import pandas as pd
import pytest

from mawi_context.hashing import sha256_file, stable_json_hash
from mawi_context.manifests import (
    artifact_record, cohort_identity, load_json_object,
    resolve_artifact_path, write_json_atomically,
)


IDENTITY_COLUMNS = (
    'target_flow_id', 'protocol', 'src_ip', 'src_port',
    'dst_ip', 'dst_port', 'context_source_ip',
)


@pytest.fixture
def cohort():
    return pd.DataFrame([
        [7, 6, '192.0.2.1', 1234, '192.0.2.2', 80, '192.0.2.1'],
        [10, 17, '2001:db8::1', 53, '2001:db8::2', 4321, '2001:db8::1'],
    ], columns=IDENTITY_COLUMNS)


def test_sha256_known_file_bytes(tmp_path):
    path = tmp_path / 'bytes'
    path.write_bytes(b'abc')
    assert sha256_file(path) == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'


def test_sha256_reads_large_file_in_bounded_chunks(tmp_path, monkeypatch):
    path = tmp_path / 'large'
    data = bytes(range(256)) * (32 * 1024)
    path.write_bytes(data)
    original_open = Path.open
    sizes = []

    class BoundedReader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, size=-1):
            assert 0 < size <= 1024 * 1024
            sizes.append(size)
            return self.stream.read(size)

    def open_bounded(self, *args, **kwargs):
        return BoundedReader(original_open(self, *args, **kwargs))

    monkeypatch.setattr(Path, 'open', open_bounded)
    assert sha256_file(path) == hashlib.sha256(data).hexdigest()
    assert len(sizes) > 2
    assert len(set(sizes)) == 1


def test_json_hash_canonical_utf8_and_nested_key_order():
    left = {'z': [True, None, {'b': 2, 'a': '日本語'}], 'a': 1}
    right = {'a': 1, 'z': [True, None, {'a': '日本語', 'b': 2}]}
    canonical = '{"a":1,"z":[true,null,{"a":"日本語","b":2}]}'
    expected = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
    assert stable_json_hash(left) == stable_json_hash(right) == expected
    assert stable_json_hash(json.loads(json.dumps(left, indent=4))) == expected


def test_json_hash_changes_with_value():
    assert stable_json_hash({'a': 1}) != stable_json_hash({'a': 2})
    assert stable_json_hash([1, 2]) != stable_json_hash([2, 1])
    # Stdlib JSON number spelling is preserved, without numeric coercion.
    assert stable_json_hash(1) != stable_json_hash(1.0)


@pytest.mark.parametrize('value', [float('nan'), float('inf'), -float('inf')])
def test_json_hash_rejects_nonstandard_numbers(value):
    with pytest.raises(ValueError):
        stable_json_hash({'nested': [value]})


def test_json_hash_has_no_repr_fallback():
    with pytest.raises(TypeError):
        stable_json_hash({'bad': object()})


def test_atomic_json_roundtrip_utf8_mapping_and_parent_creation(tmp_path):
    path = tmp_path / 'new' / 'manifest.json'
    value = {'name': '研究', 'nested': {'rows': [1, None, True]}}
    write_json_atomically(path, MappingProxyType(value))
    assert load_json_object(path) == value
    assert '研究' in path.read_text(encoding='utf-8')
    assert list(path.parent.iterdir()) == [path]


def test_atomic_json_replaces_existing_object(tmp_path):
    path = tmp_path / 'manifest.json'
    path.write_text('{"old": true}', encoding='utf-8')
    write_json_atomically(path, {'new': 2})
    assert load_json_object(path) == {'new': 2}
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize('existing', [False, True])
@pytest.mark.parametrize('bad', [object(), float('nan')])
def test_serialization_failure_preserves_target_and_cleans_temp(tmp_path, existing, bad):
    path = tmp_path / 'manifest.json'
    before = b'{"valid": true}\n'
    if existing:
        path.write_bytes(before)
    with pytest.raises((TypeError, ValueError)):
        write_json_atomically(path, {'partial': [1, 2], 'bad': bad})
    assert path.read_bytes() == before if existing else not path.exists()
    assert list(tmp_path.iterdir()) == ([path] if existing else [])


@pytest.mark.parametrize('operation', ['fsync', 'replace'])
@pytest.mark.parametrize('existing', [False, True])
def test_io_failure_preserves_target_and_cleans_temp(tmp_path, monkeypatch, operation, existing):
    path = tmp_path / 'manifest.json'
    before = b'{"valid": true}'
    if existing:
        path.write_bytes(before)

    def fail(*args):
        raise OSError('injected I/O failure')

    monkeypatch.setattr(f'mawi_context.manifests.os.{operation}', fail)
    with pytest.raises(OSError, match='injected'):
        write_json_atomically(path, {'new': 2})
    assert path.read_bytes() == before if existing else not path.exists()
    assert list(tmp_path.iterdir()) == ([path] if existing else [])


@pytest.mark.parametrize('value', [[], 'text', 1, None])
def test_atomic_writer_requires_object_root(tmp_path, value):
    with pytest.raises(TypeError):
        write_json_atomically(tmp_path / 'manifest.json', value)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('text', ['{', '{"x": NaN}', '{"x": Infinity}'])
def test_load_rejects_malformed_or_nonstandard_json(tmp_path, text):
    path = tmp_path / 'manifest.json'
    path.write_text(text, encoding='utf-8')
    with pytest.raises(ValueError):
        load_json_object(path)


@pytest.mark.parametrize('text', ['[]', '"text"', '1', 'null', 'true'])
def test_load_requires_object_root(tmp_path, text):
    path = tmp_path / 'manifest.json'
    path.write_text(text, encoding='utf-8')
    with pytest.raises(ValueError):
        load_json_object(path)


def test_cohort_identity_ignores_index_row_and_column_order(cohort):
    before = cohort.copy(deep=True)
    reordered = cohort.iloc[::-1, ::-1].copy()
    reordered.index = ['other', 'index']
    assert cohort_identity(cohort) == cohort_identity(reordered)
    assert len(cohort_identity(cohort)) == 64
    pd.testing.assert_frame_equal(cohort, before)


@pytest.mark.parametrize('column', [
    'target_start_time', 'target_end_time', 'target_duration',
    'observed_packet_count', 'context_source_basis', 'ip_version',
    'initial_syn_sender_ip', 'analysis_note',
])
def test_non_retention_facts_do_not_change_identity(cohort, column):
    changed = cohort.copy()
    changed[column] = ['unrelated', None]
    assert cohort_identity(cohort) == cohort_identity(changed)


@pytest.mark.parametrize('column,value', [
    ('target_flow_id', 99), ('protocol', 17), ('src_ip', '192.0.2.3'),
    ('dst_ip', '192.0.2.4'), ('src_port', 555), ('dst_port', 443),
    ('context_source_ip', '192.0.2.2'),
])
def test_each_retention_fact_changes_identity(cohort, column, value):
    changed = cohort.copy()
    changed.loc[0, column] = value
    assert cohort_identity(cohort) != cohort_identity(changed)


def test_cohort_row_addition_deletion_and_empty_identity(cohort):
    identity = cohort_identity(cohort)
    assert identity != cohort_identity(cohort.iloc[:1])
    # Duplicate rows still constitute a row addition, not silent deduplication.
    assert identity != cohort_identity(pd.concat([cohort, cohort.iloc[:1]]))
    empty = cohort.iloc[:0]
    assert identity != cohort_identity(empty)
    assert cohort_identity(empty) == cohort_identity(empty.copy())


def test_reversed_endpoints_preserve_retention_identity(cohort):
    changed = cohort.copy()
    changed[['src_ip', 'src_port', 'dst_ip', 'dst_port']] = cohort[
        ['dst_ip', 'dst_port', 'src_ip', 'src_port']
    ].to_numpy()
    assert cohort_identity(changed) == cohort_identity(cohort)


def test_endpoint_ip_and_numpy_integer_canonicalization(cohort):
    changed = cohort.astype(object)
    changed.loc[1, 'src_ip'] = '2001:0db8:0:0:0:0:0:1'
    for column in ['target_flow_id', 'protocol', 'src_port', 'dst_port']:
        changed[column] = pd.Series([np.int64(v) for v in changed[column]], dtype=object)
    assert cohort_identity(changed) == cohort_identity(cohort)


def test_context_source_text_matches_task_three_set_semantics(cohort):
    changed = cohort.copy()
    changed.loc[1, 'context_source_ip'] = '2001:0db8:0:0:0:0:0:1'
    assert cohort_identity(changed) != cohort_identity(cohort)


@pytest.mark.parametrize('column', IDENTITY_COLUMNS)
def test_cohort_missing_identity_column_fails(cohort, column):
    with pytest.raises(ValueError, match=column):
        cohort_identity(cohort.drop(columns=column))


@pytest.mark.parametrize('column', IDENTITY_COLUMNS)
@pytest.mark.parametrize('missing', [None, float('nan'), pd.NA])
def test_cohort_null_identity_fact_fails(cohort, column, missing):
    changed = cohort.astype(object)
    changed.loc[0, column] = missing
    with pytest.raises(ValueError, match=column):
        cohort_identity(changed)


@pytest.mark.parametrize('column,value', [
    ('target_flow_id', True), ('target_flow_id', 1.5), ('target_flow_id', 0),
    ('protocol', '6'), ('protocol', 1), ('src_port', -1),
    ('dst_port', 65536), ('src_port', True), ('src_ip', 'nan'),
    ('dst_ip', 123), ('context_source_ip', ''), ('context_source_ip', 'nan'),
])
def test_invalid_identity_facts_fail(cohort, column, value):
    changed = cohort.astype(object)
    changed.loc[0, column] = value
    with pytest.raises(ValueError):
        cohort_identity(changed)


def test_cohort_rejects_conflicting_lookup_identities(cohort):
    changed = cohort.copy()
    changed.loc[1, 'target_flow_id'] = 7
    with pytest.raises(ValueError, match='target_flow_id'):
        cohort_identity(changed)
    changed = cohort.iloc[[0]].copy()
    changed['target_flow_id'] = 99
    with pytest.raises(ValueError, match='FlowKey'):
        cohort_identity(pd.concat([cohort, changed]))


def test_cohort_rejects_duplicate_identity_columns(cohort):
    with pytest.raises(ValueError):
        cohort_identity(pd.concat([cohort, cohort[['src_ip']]], axis=1))


@pytest.fixture
def artifact(tmp_path):
    root = tmp_path / 'root_a'
    path = root / 'cohort' / 'target_cohort.csv'
    path.parent.mkdir(parents=True)
    path.write_bytes(b'abc')
    return root, path


def test_artifact_record_exact_portable_contract(artifact):
    root, path = artifact
    record = artifact_record(root, path, row_count=3, schema_version='v1')
    assert record == {
        'path': 'cohort/target_cohort.csv',
        'sha256': 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        'row_count': 3, 'schema_version': 'v1',
    }
    assert str(root) not in json.dumps(record)
    assert '\\' not in record['path']
    assert artifact_record(root, path, row_count=0, schema_version='v1')['row_count'] == 0


def test_artifact_outside_dataset_is_rejected(artifact, tmp_path):
    root, _ = artifact
    outside = tmp_path / 'outside'
    outside.write_bytes(b'abc')
    with pytest.raises(ValueError):
        artifact_record(root, outside, row_count=1, schema_version='v1')


@pytest.mark.parametrize('count', [-1, True, 1.5, '1', None])
def test_invalid_row_count_rejected(artifact, count):
    root, path = artifact
    with pytest.raises(ValueError, match='row_count'):
        artifact_record(root, path, row_count=count, schema_version='v1')


@pytest.mark.parametrize('version', ['', '  ', None, 1])
def test_invalid_schema_version_rejected(artifact, version):
    root, path = artifact
    with pytest.raises(ValueError, match='schema_version'):
        artifact_record(root, path, row_count=1, schema_version=version)


def test_missing_artifact_fails(artifact):
    root, _ = artifact
    with pytest.raises(FileNotFoundError):
        artifact_record(root, root / 'missing', row_count=0, schema_version='v1')


def test_resolver_normal_relative_and_not_yet_existing_path(artifact):
    root, path = artifact
    assert resolve_artifact_path(root, 'cohort/target_cohort.csv') == path
    assert resolve_artifact_path(root, 'future/file') == root / 'future/file'


@pytest.mark.parametrize('path', [
    '/absolute/path', '../outside', 'a/../../outside', 'a/../inside',
    'C:\\local\\file', 'C:/local/file', 'C:file', '\\\\server\\file',
    'a\\file', '', '.', './a', 'a//b', 'a/',
])
def test_resolver_rejects_nonportable_or_escaping_paths(artifact, path):
    root, _ = artifact
    with pytest.raises(ValueError):
        resolve_artifact_path(root, path)


def test_portable_copy_preserves_record_and_identity(artifact, tmp_path):
    root_a, path = artifact
    record = artifact_record(root_a, path, row_count=1, schema_version='v1')
    identity = stable_json_hash(record)
    write_json_atomically(root_a / 'manifest.json', record)
    root_b = tmp_path / 'root_b'
    shutil.copytree(root_a, root_b)
    shutil.rmtree(root_a)
    loaded = load_json_object(root_b / 'manifest.json')
    copied = resolve_artifact_path(root_b, loaded['path'])
    assert copied.read_bytes() == b'abc'
    assert artifact_record(root_b, copied, row_count=1, schema_version='v1') == record
    assert stable_json_hash(loaded) == identity
    assert str(root_a) not in json.dumps(loaded)


@pytest.mark.parametrize('directory_link', [False, True])
def test_symlink_escape_rejected(artifact, tmp_path, directory_link):
    root, _ = artifact
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'file').write_bytes(b'abc')
    link = root / 'escape'
    try:
        link.symlink_to(outside if directory_link else outside / 'file',
                        target_is_directory=directory_link)
    except (OSError, NotImplementedError):
        pytest.skip('symlinks unavailable')
    relative = 'escape/file' if directory_link else 'escape'
    with pytest.raises(ValueError):
        resolve_artifact_path(root, relative)
    with pytest.raises(ValueError):
        artifact_record(root, root / relative, row_count=1, schema_version='v1')
