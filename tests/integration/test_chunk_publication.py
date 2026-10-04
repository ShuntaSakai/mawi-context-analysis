"""Durable single-chunk publication; all captures are synthetic."""
from dataclasses import asdict
import json
from pathlib import Path
import shutil
import sys

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'helpers'))
from pcap_factory import packet, pcap_bytes, write_capture
from mawi_context import observations as obs
from mawi_context.observations import RawSourceIdentity, extract_chunk_observations, load_validated_chunk
from mawi_context.cohort import ContextIndexes
from mawi_context.flow import FlowKey
from mawi_context.hashing import sha256_file

CHUNK = 'tiny-chunk'
COHORT = 'a'*64


@pytest.fixture
def case(tmp_path):
    capture = write_capture(tmp_path/'raw.pcap', [(1.125, packet(), 54)])
    source = RawSourceIdentity(CHUNK, 'https://example.org/raw.pcap', sha256_file(capture), capture.stat().st_size)
    indexes = ContextIndexes({FlowKey.from_packet('192.0.2.10', 1234, '192.0.2.2', 80, 6): 42},
                             frozenset({'192.0.2.10'}))
    return capture, indexes, tmp_path/'dataset', source


def extract(case, **kwargs):
    capture, indexes, root, source = case
    return extract_chunk_observations(capture, indexes, root, CHUNK, source,
                                      cohort_identity_value=kwargs.pop('cohort', COHORT), **kwargs)


def final(case):
    return case[2]/'observations'/CHUNK


def read_manifest(case):
    return json.loads((final(case)/'manifest.json').read_text())


def write_manifest(case, manifest):
    (final(case)/'manifest.json').write_text(json.dumps(manifest))


def snapshot(directory):
    return {p.name: p.read_bytes() for p in directory.iterdir() if p.is_file()}


def test_success_exact_portable_manifest_checksums_counts_versions_and_reload(case, monkeypatch):
    writes, validates, publishes, reloads = [], [], [], []
    original_write = obs._write_observations
    original_validate = obs._validate_chunk
    original_publish = obs._publish_chunk
    original_load = obs.load_validated_chunk
    def write(capture, indexes, staging):
        assert staging.parent == case[2]/'observations'
        assert staging.name.startswith('.staging-tiny-chunk-')
        assert staging != final(case)
        assert not final(case).exists()
        writes.append(staging)
        return original_write(capture, indexes, staging)
    def validate(*args, **kwargs):
        validates.append(args[1])
        return original_validate(*args, **kwargs)
    def publish(staging, destination):
        assert validates == [staging]
        assert (staging/'manifest.json').is_file()
        publishes.append((staging, destination))
        return original_publish(staging, destination)
    def load(*args, **kwargs):
        assert final(case).is_dir()
        reloads.append(args)
        return original_load(*args, **kwargs)
    monkeypatch.setattr(obs, '_write_observations', write)
    monkeypatch.setattr(obs, '_validate_chunk', validate)
    monkeypatch.setattr(obs, '_publish_chunk', publish)
    monkeypatch.setattr(obs, 'load_validated_chunk', load)
    manifest = extract(case)
    assert len(writes) == len(publishes) == len(reloads) == 1
    assert not writes[0].exists()
    assert set(p.name for p in final(case).iterdir()) == {'manifest.json', 'target_packets.parquet', 'source_context_packets.parquet'}
    assert set(manifest) == {'manifest_schema_version', 'status', 'chunk_id', 'cohort_identity', 'source', 'artifacts'}
    assert manifest['manifest_schema_version'] == obs.CHUNK_MANIFEST_SCHEMA_VERSION == 'chunk-manifest-v1'
    assert manifest['status'] == 'success'
    assert manifest['chunk_id'] == CHUNK
    assert manifest['cohort_identity'] == COHORT
    assert manifest['source'] == asdict(case[3])
    assert set(manifest['artifacts']) == {'target_packets', 'source_context_packets'}
    versions = {'target_packets': 'target-packets-v1', 'source_context_packets': 'source-context-packets-v1'}
    assert obs.TARGET_PACKET_SCHEMA_VERSION == versions['target_packets']
    assert obs.SOURCE_CONTEXT_SCHEMA_VERSION == versions['source_context_packets']
    for name, version in versions.items():
        record = manifest['artifacts'][name]
        path = final(case)/f'{name}.parquet'
        assert set(record) == {'path', 'sha256', 'row_count', 'schema_version'}
        assert record['path'] == f'observations/{CHUNK}/{name}.parquet'
        assert record['sha256'] == sha256_file(path)
        assert record['row_count'] == pq.ParquetFile(path).metadata.num_rows == 1
        assert record['schema_version'] == version
    content = (final(case)/'manifest.json').read_text()
    assert str(case[0]) not in content and str(case[2]) not in content
    assert '.staging-' not in content
    assert original_load(case[2], CHUNK, expected_cohort_identity=COHORT) == manifest
    assert case[0].is_file()


@pytest.mark.parametrize('chunk', ['', '.', '..', 'a/b', 'a\\b', '/absolute', 'C:drive', 'nul\x00'])
def test_chunk_component_safety(case, chunk):
    with pytest.raises(ValueError):
        RawSourceIdentity(chunk, 'url', 'a'*64, 0)
    with pytest.raises(ValueError):
        load_validated_chunk(case[2], chunk, expected_cohort_identity=COHORT)
    with pytest.raises(ValueError):
        extract_chunk_observations(case[0], case[1], case[2], chunk, case[3], cohort_identity_value=COHORT)
    assert not case[2].exists()


@pytest.mark.parametrize('field,value', [
    ('source_url', ''), ('source_url', '   '), ('source_url', 1),
    ('sha256', 'A'*64), ('sha256', 'g'*64), ('sha256', 'a'*63), ('sha256', None),
    ('size_bytes', -1), ('size_bytes', True), ('size_bytes', 1.0),
])
def test_raw_source_value_contract(field, value):
    args = dict(chunk_id=CHUNK, source_url='any-nonempty-url', sha256='a'*64, size_bytes=0)
    args[field] = value
    with pytest.raises(ValueError):
        RawSourceIdentity(**args)


@pytest.mark.parametrize('kind', ['size', 'sha', 'chunk', 'cohort-empty', 'cohort-uppercase', 'cohort-invalid'])
def test_invalid_identity_rejected_before_scan(case, monkeypatch, kind):
    capture, indexes, root, source = case
    facts = asdict(source)
    cohort = COHORT
    if kind == 'size':
        facts['size_bytes'] += 1
    elif kind == 'sha':
        facts['sha256'] = 'b'*64
    elif kind == 'chunk':
        facts['chunk_id'] = 'other'
    else:
        cohort = {'cohort-empty': '', 'cohort-uppercase': 'A'*64, 'cohort-invalid': 'z'*64}[kind]
    def forbidden(*args, **kwargs):
        pytest.fail('invalid identity must be rejected before scanning')
    monkeypatch.setattr(obs, '_write_observations', forbidden)
    with pytest.raises(ValueError):
        extract_chunk_observations(capture, indexes, root, CHUNK, RawSourceIdentity(**facts), cohort_identity_value=cohort)
    assert not final(case).exists()
    assert capture.is_file()


@pytest.mark.parametrize('failure', ['packet', 'capture', 'parquet', 'manifest', 'staged-validation', 'publish', 'final-reload'])
def test_failure_leaves_no_final_cleans_only_own_staging_and_keeps_raw(case, monkeypatch, failure):
    capture, indexes, root, source = case
    parent = root/'observations'
    parent.mkdir(parents=True)
    unrelated = parent/'.staging-other-owner'
    unrelated.mkdir()
    (unrelated/'keep').write_text('keep')
    if failure in ('packet', 'capture'):
        capture.write_bytes(pcap_bytes([(1, packet(), 54)]) + b'broken' if failure == 'capture'
                            else pcap_bytes([(1, packet(), 54), (2, b'\x00'*12, 12)]))
        source = RawSourceIdentity(CHUNK, source.source_url, sha256_file(capture), capture.stat().st_size)
        case = capture, indexes, root, source
    def fail(*args, **kwargs):
        raise OSError('injected failure')
    if failure == 'parquet':
        monkeypatch.setattr(obs.pq.ParquetWriter, 'write_table', fail)
    elif failure == 'manifest':
        monkeypatch.setattr(obs, 'write_json_atomically', fail)
    elif failure == 'staged-validation':
        monkeypatch.setattr(obs, '_validate_chunk', fail)
    elif failure == 'publish':
        monkeypatch.setattr(obs, '_publish_chunk', fail)
    elif failure == 'final-reload':
        monkeypatch.setattr(obs, 'load_validated_chunk', fail)
    with pytest.raises((ValueError, OSError)):
        extract(case)
    assert not final(case).exists()
    assert set(parent.iterdir()) == {unrelated}
    assert (unrelated/'keep').read_text() == 'keep'
    assert capture.is_file()


def test_same_identity_reuses_without_scanning_or_writing(case, monkeypatch):
    manifest = extract(case)
    before = snapshot(final(case))
    def forbidden(*args, **kwargs):
        pytest.fail('compatible cache must be reused')
    monkeypatch.setattr(obs, '_write_observations', forbidden)
    assert extract(case) == manifest
    assert snapshot(final(case)) == before
    assert not list((case[2]/'observations').glob('.staging-*'))


@pytest.mark.parametrize('mismatch', ['cohort', 'source'])
def test_existing_identity_mismatch_is_immutable(case, mismatch):
    extract(case)
    before = snapshot(final(case))
    if mismatch == 'cohort':
        with pytest.raises(ValueError):
            extract(case, cohort='b'*64)
    else:
        capture, indexes, root, source = case
        source = RawSourceIdentity(CHUNK, 'https://other.example/raw', source.sha256, source.size_bytes)
        with pytest.raises(ValueError):
            extract((capture, indexes, root, source))
    assert snapshot(final(case)) == before


@pytest.mark.parametrize('damage', [
    'checksum', 'schema', 'row-count', 'extra', 'missing', 'path', 'artifact-version',
    'manifest-version', 'status', 'chunk', 'source-chunk', 'source-sha', 'source-size',
    'source-url', 'source-extra', 'artifact-extra', 'artifact-bool-count', 'root-extra',
    'artifacts-missing', 'not-json', 'not-object', 'nonstandard-json', 'symlink',
])
def test_corrupt_existing_cache_rejected_without_overwrite(case, damage):
    extract(case)
    manifest = read_manifest(case)
    artifact = manifest['artifacts']['target_packets']
    path = final(case)/'target_packets.parquet'
    if damage == 'checksum':
        path.write_bytes(path.read_bytes()+b'corruption')
    elif damage == 'schema':
        pq.write_table(pa.table({'wrong': [1]}), path)
        artifact['sha256'] = sha256_file(path)
    elif damage == 'row-count':
        artifact['row_count'] = 2
    elif damage == 'extra':
        (final(case)/'unexpected').write_text('extra')
    elif damage == 'missing':
        path.unlink()
    elif damage == 'path':
        artifact['path'] = 'observations/elsewhere/target_packets.parquet'
    elif damage == 'artifact-version':
        artifact['schema_version'] = 'future'
    elif damage == 'manifest-version':
        manifest['manifest_schema_version'] = 'future'
    elif damage == 'status':
        manifest['status'] = 'failed'
    elif damage == 'chunk':
        manifest['chunk_id'] = 'elsewhere'
    elif damage.startswith('source-'):
        key, value = {'source-chunk': ('chunk_id', 'other'), 'source-sha': ('sha256', 'BAD'),
                      'source-size': ('size_bytes', True), 'source-url': ('source_url', ''),
                      'source-extra': ('extra', 1)}[damage]
        manifest['source'][key] = value
    elif damage == 'artifact-extra':
        artifact['extra'] = 1
    elif damage == 'artifact-bool-count':
        artifact['row_count'] = True
    elif damage == 'root-extra':
        manifest['extra'] = 1
    elif damage == 'artifacts-missing':
        manifest['artifacts'].pop('source_context_packets')
    elif damage == 'symlink':
        outside = case[0].parent/'external.parquet'
        shutil.copyfile(path, outside)
        path.unlink()
        path.symlink_to(outside)
    if damage in ('not-json', 'not-object', 'nonstandard-json'):
        (final(case)/'manifest.json').write_text({'not-json': '{', 'not-object': '[]', 'nonstandard-json': '{"x": NaN}'}[damage])
    else:
        write_manifest(case, manifest)
    before = snapshot(final(case))
    with pytest.raises((ValueError, OSError)):
        load_validated_chunk(case[2], CHUNK, expected_cohort_identity=COHORT)
    with pytest.raises((ValueError, OSError)):
        extract(case)
    assert snapshot(final(case)) == before
    assert final(case).is_dir()
    assert case[0].is_file()


def test_portable_copy_loads_without_raw_or_original_dataset(case, tmp_path):
    manifest = extract(case)
    copied = tmp_path/'portable-copy'
    shutil.copytree(case[2], copied)
    shutil.rmtree(case[2])
    case[0].unlink()
    assert load_validated_chunk(copied, CHUNK, expected_cohort_identity=COHORT) == manifest


def test_publication_never_replaces_existing_empty_directory(tmp_path):
    staging, destination = tmp_path/'stage', tmp_path/'final'
    staging.mkdir()
    (staging/'evidence').write_text('new')
    destination.mkdir()
    with pytest.raises(FileExistsError):
        obs._publish_chunk(staging, destination)
    assert destination.is_dir() and list(destination.iterdir()) == []
    assert (staging/'evidence').is_file()


def test_interruption_after_atomic_rename_rolls_back_only_owned_final(case, monkeypatch):
    publish = obs._publish_chunk
    def interrupted(staging, destination):
        publish(staging, destination)
        if destination == final(case):
            raise KeyboardInterrupt('interrupted after rename before return')
    monkeypatch.setattr(obs, '_publish_chunk', interrupted)
    with pytest.raises(KeyboardInterrupt):
        extract(case)
    assert not final(case).exists()
    assert not list((case[2]/'observations').glob('.staging-*'))
    assert case[0].is_file()
