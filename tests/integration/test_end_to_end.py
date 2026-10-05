"""CLI acceptance of the production 96-chunk workflow, entirely synthetic."""
from concurrent.futures import ProcessPoolExecutor
import csv
from datetime import datetime, timezone
import gzip
from io import BytesIO
from pathlib import Path
import shutil
import socket
import sys
import urllib.request

import pyarrow as pa
import pyarrow.parquet as pq

from mawi_context import aggregation as ag, capture, downloader as dl
from mawi_context import extraction as ex, flow, observations as obs
from mawi_context.chunks import expected_chunk_ids, render_ditl_chunk_url
from mawi_context.cli import main
from mawi_context.cohort import COHORT_COLUMNS
from mawi_context.manifests import load_json_object, resolve_artifact_path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'helpers'))
from pcap_factory import packet, pcap_bytes


DAY = '2026-04-08'
TARGET = '202604081400'
FORBIDDEN_FIELD_WORDS = {
    'scan', 'malicious', 'benign', 'attack', 'anomaly',
    'client', 'server', 'attacker', 'victim',
}


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in root.rglob('*') if p.is_file()}


def assert_descriptive_fields(fields):
    for field in fields:
        assert not (set(field.lower().replace('-', '_').split('_'))
                    & FORBIDDEN_FIELD_WORDS), field


def check_manifest_fields(value, root, paths):
    """Inspect field names and path fields, allowing legitimate HTTPS URLs."""
    if isinstance(value, dict):
        assert_descriptive_fields(value)
        for key, child in value.items():
            if key in {'path', 'manifest', 'flow_manifest', 'cohort_manifest'}:
                assert isinstance(child, str)
                assert not Path(child).is_absolute()
                assert resolve_artifact_path(root, child).is_file()
                paths.append(child)
            check_manifest_fields(child, root, paths)
    elif isinstance(value, list):
        for child in value:
            check_manifest_fields(child, root, paths)


def synthetic_responses():
    """Realistic chunk timestamps; include reverse direction and a long gap."""
    t = datetime(2026, 4, 8, 14, tzinfo=timezone.utc).timestamp()
    payload = b'SYNTHETIC_APPLICATION_BYTES_MUST_NOT_BE_PERSISTED'
    tcp1 = packet(payload=payload)
    tcp1_reverse = packet(src='192.0.2.2', dst='192.0.2.10',
                          sport=80, dport=1234, flags=18)
    udp2 = packet(src='192.0.2.20', sport=2222, protocol=17, payload=payload)
    udp2_reverse = packet(src='192.0.2.2', dst='192.0.2.20',
                          sport=80, dport=2222, protocol=17)
    tcp3_reverse = packet(src='192.0.2.3', dst='192.0.2.30',
                          sport=80, dport=3333, flags=18)
    tcp3 = packet(src='192.0.2.30', dst='192.0.2.3', sport=3333)
    fallback1 = packet(src='192.0.2.40', sport=4444, flags=16)
    excluded4 = packet(src='198.51.100.1', sport=5555)
    records = {
        TARGET: [(t+10, tcp1), (t+20, udp2), (t+25, udp2_reverse),
                 (t+30, tcp3_reverse), (t+31, tcp3), (t+40, fallback1),
                 *[(t+50+i, excluded4) for i in range(4)],
                 (t+800, packet(src='192.0.2.30', dst='192.0.2.3',
                                sport=3333, flags=16))],
        '202604081345': [
            (t-10, udp2),
            (t-5, packet(src='192.0.2.2', dst='192.0.2.10',
                          sport=80, dport=1234, flags=16)),
            (t-2, packet(dst='198.51.100.2', dport=443)),
        ],
        '202604081415': [
            (t+905, tcp1_reverse),
            (t+910, packet(src='192.0.2.20', dst='198.51.100.3',
                           sport=2222, dport=53, protocol=17)),
        ],
    }
    bodies = {chunk: gzip.compress(pcap_bytes(
        (timestamp, frame, len(frame)) for timestamp, frame in rows), mtime=0)
        for chunk, rows in records.items()}
    empty = gzip.compress(pcap_bytes(), mtime=0)
    return bodies, empty, payload


def test_extract_reuse_copy_and_aggregate_cli(tmp_path, monkeypatch):
    ids = expected_chunk_ids(DAY)
    assert len(ids) == len(set(ids)) == 96
    assert ids[56] == TARGET
    extraction_root = tmp_path / 'extraction'
    extraction_root.mkdir()
    monkeypatch.chdir(extraction_root)
    bodies, empty, payload = synthetic_responses()
    acquired, forbidden_calls, deleted = [], [], []

    def forbidden(*args, **kwargs):
        forbidden_calls.append(args)
        raise AssertionError('network, raw reconstruction, or rescan forbidden')

    class Response(BytesIO):
        def __init__(self, body):
            super().__init__(body)
            self.headers = {'Content-Length': str(len(body))}

    def opener(url, timeout):
        chunk = url.rsplit('/', 1)[-1].removesuffix('.pcap.gz')
        assert chunk in ids
        assert url == render_ditl_chunk_url(DAY, chunk)
        acquired.append(chunk)
        return Response(bodies.get(chunk, empty))

    monkeypatch.setattr(urllib.request, 'urlopen', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(dl, 'urlopen', opener)
    # Observe deletion in the real parent, after its final reload succeeds.
    delete = ex._delete_owned_raw

    def checked_delete(source, spool):
        root = extraction_root / 'data' / TARGET / 'portable_dataset'
        dm = load_json_object(root / 'dataset_manifest.json')
        manifest = obs.load_validated_chunk(
            root, source.chunk_id, expected_cohort_identity=dm['cohort_identity'])
        assert manifest['source']['sha256'] == source.sha256
        deleted.append(source.chunk_id)
        delete(source, spool)

    monkeypatch.setattr(ex, '_delete_owned_raw', checked_delete)
    args = ['extract', '--day', DAY, '--target-chunk', TARGET,
            '--packet-counts', '1', '2', '3', '--workers', '2']
    # Use the actual ProcessPoolExecutor and public CLI; only HTTP is synthetic.
    assert main(args) == 0
    dataset = extraction_root / 'data' / TARGET / 'portable_dataset'
    spool = extraction_root / 'data' / TARGET / 'spool'
    assert dataset.is_dir() and spool.is_dir()
    assert set(acquired) == set(deleted) == set(ids)
    assert len(acquired) == len(deleted) == 96
    assert acquired[0] == TARGET
    assert list(spool.iterdir()) == []
    dm = load_json_object(dataset / 'dataset_manifest.json')
    assert dm['status'] == 'success'
    assert dm['packet_counts'] == [1, 2, 3]
    assert dm['expected_chunk_ids'] == list(ids)
    assert {p.name for p in (dataset / 'observations').iterdir()} == set(ids)
    assert all(state['status'] == 'success' for state in dm['chunks'].values())
    with (dataset / 'provenance/flows.csv').open(newline='') as stream:
        reader = csv.DictReader(stream)
        assert tuple(reader.fieldnames) == flow.FLOW_COLUMNS
        assert_descriptive_fields(reader.fieldnames)
        assert sorted(int(row['packet_count']) for row in reader) == [1, 1, 2, 3, 4]
    with (dataset / 'cohort/target_cohort.csv').open(newline='') as stream:
        reader = csv.DictReader(stream)
        assert tuple(reader.fieldnames) == COHORT_COLUMNS
        assert_descriptive_fields(reader.fieldnames)
        cohort = list(reader)
    assert [int(row['observed_packet_count']) for row in cohort] == [1, 2, 3, 1]
    three = cohort[2]
    assert three['src_ip'] == '192.0.2.3'
    assert three['context_source_ip'] == '192.0.2.30'
    assert three['context_source_basis'] == 'initial_syn_sender'
    assert float(three['target_duration']) == 770
    assert cohort[1]['context_source_basis'] == cohort[3]['context_source_basis'] == 'first_observed_src'
    assert cohort[0]['target_start_time'] == cohort[0]['target_end_time']
    assert not list(dataset.rglob('packet_count_*'))  # one shared cohort/cache

    paths = []
    for path in dataset.rglob('*.json'):
        text = path.read_text()
        for local in (dataset, spool, extraction_root):
            assert str(local) not in text
        for staging_prefix in ('.staging-', '.provenance-', '.cohort-'):
            assert staging_prefix not in text
        check_manifest_fields(load_json_object(path), dataset, paths)
    assert len(paths) == 292  # 2 manifest refs + 96 refs + 2 CSVs + 192 Parquets
    for chunk in ids:
        obs.load_validated_chunk(dataset, chunk, expected_cohort_identity=dm['cohort_identity'])
        for name, schema in [('target_packets', obs.TARGET_PACKET_SCHEMA),
                             ('source_context_packets', obs.SOURCE_CONTEXT_SCHEMA)]:
            actual = pq.read_schema(dataset / 'observations' / chunk / f'{name}.parquet')
            assert actual.equals(schema, check_metadata=True)
            assert_descriptive_fields(actual.names)
            assert not any(pa.types.is_binary(field.type) or pa.types.is_large_binary(field.type)
                           for field in actual)
    before = snapshot(dataset)
    assert all(payload not in content for content in before.values())

    # A valid rerun must never submit a scan or acquire/reconstruct target raw.
    class NoScans(ProcessPoolExecutor):
        def submit(self, *args, **kwargs):
            return forbidden(*args, **kwargs)

    monkeypatch.setattr(ex, 'ProcessPoolExecutor', NoScans)
    monkeypatch.setattr(dl, 'urlopen', forbidden)
    monkeypatch.setattr(dl, 'download_chunk', forbidden)
    monkeypatch.setattr(ex, 'download_chunk', forbidden)
    monkeypatch.setattr(ex, 'parse_target_flows', forbidden)
    assert main(args) == 0
    assert forbidden_calls == []
    assert snapshot(dataset) == before

    copied = Path(shutil.copytree(dataset, tmp_path / 'copied_portable_dataset'))
    monkeypatch.chdir(tmp_path)
    shutil.rmtree(extraction_root)  # original dataset, spool, and any raw inputs
    bodies.clear()  # synthetic response bytes no longer available either
    assert not extraction_root.exists()
    assert not list(tmp_path.rglob('*.pcap*'))
    monkeypatch.setattr(ex, 'run_extract', forbidden)
    monkeypatch.setattr(ex, '_target_provenance', forbidden)
    monkeypatch.setattr(flow, 'parse_target_flows', forbidden)
    for module in (capture, flow, obs):
        monkeypatch.setattr(module, 'iter_capture_records', forbidden)
    sqlite_connect = ag.sqlite3.connect
    sqlite_paths = []

    def connect(path, *args, **kwargs):
        sqlite_paths.append(Path(path).resolve())
        assert not Path(path).resolve().is_relative_to(copied)
        return sqlite_connect(path, *args, **kwargs)

    monkeypatch.setattr(ag.sqlite3, 'connect', connect)
    copied_before = snapshot(copied)
    assert main(['aggregate', '--dataset', str(copied)]) == 0
    assert forbidden_calls == []
    assert snapshot(copied) == copied_before == before
    output = tmp_path / 'results' / TARGET
    assert len(sqlite_paths) == 1 and sqlite_paths[0].parent == output
    assert not list(output.glob('*.sqlite*'))
    assert {p.name for p in output.iterdir()} == {'packet_count_1', 'packet_count_2', 'packet_count_3'}
    rows = {}
    for count, expected_rows in [(1, 2), (2, 1), (3, 1)]:
        with (output / f'packet_count_{count}/context.csv').open(newline='') as stream:
            reader = csv.DictReader(stream)
            assert tuple(reader.fieldnames) == ag.CONTEXT_RESULT_COLUMNS
            assert_descriptive_fields(reader.fieldnames)
            rows[count] = list(reader)
        assert len(rows[count]) == expected_rows
        assert {int(row['observed_packet_count']) for row in rows[count]} == {count}
        flow_ids = [int(row['target_flow_id']) for row in rows[count]]
        assert flow_ids == sorted(flow_ids)
    one, two, three = rows[1][0], rows[2][0], rows[3][0]
    assert int(one['same_tuple_packet_count_24h']) == 3
    assert int(one['same_tuple_before_count']) == int(one['same_tuple_after_count']) == 1
    assert float(one['previous_same_tuple_gap_seconds']) == 15
    assert float(one['next_same_tuple_gap_seconds']) == 895
    assert int(one['tcp_outbound_plain_syn_count_24h']) == 2
    assert int(one['tcp_inbound_syn_ack_count_24h']) == 1
    assert int(one['tcp_control_packet_count_24h']) == 3
    assert int(one['tcp_control_packet_count_window_60s']) == 2
    assert int(two['same_tuple_packet_count_24h']) == 3
    assert int(two['same_tuple_before_count']) == 1
    assert int(two['same_tuple_after_count']) == 0
    assert float(two['previous_same_tuple_gap_seconds']) == 30
    assert two['next_same_tuple_gap_seconds'] == ''
    assert int(two['udp_outbound_packet_count_24h']) == 3
    assert int(two['udp_outbound_unique_dst_ip_count_24h']) == 2
    assert int(two['udp_outbound_packet_count_window_60s']) == 2
    assert int(three['same_tuple_packet_count_24h']) == 3
    assert int(three['tcp_outbound_plain_syn_count_24h']) == 1
    assert int(three['tcp_inbound_syn_ack_count_24h']) == 1
