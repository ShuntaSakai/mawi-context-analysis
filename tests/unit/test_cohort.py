import sys
from pathlib import Path

import pandas as pd
import pytest

from mawi_context.cohort import (
    COHORT_COLUMNS, build_context_indexes, select_target_cohort,
)
from mawi_context.flow import FLOW_COLUMNS, FlowKey, parse_target_flows

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'helpers'))
from pcap_factory import packet, write_capture


EXPECTED_COLUMNS = [
    'target_flow_id', 'observed_packet_count', 'ip_version', 'protocol',
    'src_ip', 'src_port', 'dst_ip', 'dst_port',
    'target_start_time', 'target_end_time', 'target_duration',
    'initial_syn_sender_ip', 'initial_syn_sender_port',
    'initial_syn_receiver_ip', 'initial_syn_receiver_port',
    'context_source_ip', 'context_source_basis',
]
SYN_COLUMNS = EXPECTED_COLUMNS[11:15]


@pytest.fixture
def flows():
    # Nonconsecutive IDs and mixed counts catch renumbering and count sorting.
    rows = []
    for flow_id, count, protocol, src, port in [
        (2, 3, 6, '192.0.2.1', 1000),
        (7, 1, 6, '192.0.2.1', 1001),
        (10, 2, 17, '192.0.2.3', 1002),
        (12, 4, 6, '192.0.2.4', 1003),
        (15, 7, 17, '192.0.2.5', 1004),
    ]:
        rows.append(dict(
            flow_id=flow_id, packet_count=count, ip_version=4, protocol=protocol,
            src_ip=src, src_port=port, dst_ip='192.0.2.2', dst_port=80,
            start_time=10.5, end_time=10.5+count-1, duration=count-1,
            captured_frame_bytes=54*count, original_frame_bytes=54*count,
            ip_bytes=40*count, transport_payload_bytes=0,
            initial_syn_sender_ip=None, initial_syn_sender_port=None,
            initial_syn_receiver_ip=None, initial_syn_receiver_port=None,
        ))
    rows[0].update(initial_syn_sender_ip='192.0.2.2', initial_syn_sender_port=80,
                   initial_syn_receiver_ip='192.0.2.1', initial_syn_receiver_port=1000)
    return pd.DataFrame(rows, columns=FLOW_COLUMNS, index=[9, 3, 8, 2, 1])


def test_shared_cohort_preserves_ids_counts_and_first_observation_order(flows):
    cohort = select_target_cohort(flows, (1, 2, 3))
    assert cohort.target_flow_id.tolist() == [2, 7, 10]
    assert cohort.observed_packet_count.tolist() == [3, 1, 2]
    assert list(cohort.columns) == EXPECTED_COLUMNS == list(COHORT_COLUMNS)


@pytest.mark.parametrize('original,target', [
    ('start_time', 'target_start_time'), ('end_time', 'target_end_time'),
    ('duration', 'target_duration'), ('src_ip', 'src_ip'), ('src_port', 'src_port'),
    ('dst_ip', 'dst_ip'), ('dst_port', 'dst_port'), ('protocol', 'protocol'),
    ('ip_version', 'ip_version'),
])
def test_observed_facts_are_preserved(flows, original, target):
    assert select_target_cohort(flows, (1, 2, 3))[target].tolist() == flows[original].iloc[:3].tolist()


def test_one_observed_packet_has_zero_target_interval(flows):
    row = select_target_cohort(flows, (1,)).iloc[0]
    assert row.target_start_time == row.target_end_time == 10.5
    assert row.target_duration == 0


def test_tcp_uses_observed_syn_sender_and_preserves_metadata(flows):
    row = select_target_cohort(flows, (3,)).iloc[0]
    assert row.context_source_ip == '192.0.2.2'
    assert row.context_source_basis == 'initial_syn_sender'
    assert row[SYN_COLUMNS].tolist() == ['192.0.2.2', 80, '192.0.2.1', 1000]


@pytest.mark.parametrize('missing', [None, float('nan'), pd.NA])
def test_tcp_missing_syn_falls_back_without_stringifying_null(flows, missing):
    flows.loc[3, 'initial_syn_sender_ip'] = missing
    row = select_target_cohort(flows, (1,)).iloc[0]
    assert row.context_source_ip == '192.0.2.1'
    assert row.context_source_basis == 'first_observed_src'
    assert all(pd.isna(row[column]) for column in SYN_COLUMNS)


def test_udp_uses_first_observed_source_and_preserves_null_metadata(flows):
    row = select_target_cohort(flows, (2,)).iloc[0]
    assert row.context_source_ip == '192.0.2.3'
    assert row.context_source_basis == 'first_observed_src'
    assert all(pd.isna(row[column]) for column in SYN_COLUMNS)


def test_udp_policy_does_not_use_syn_field(flows):
    flows.loc[8, 'initial_syn_sender_ip'] = '192.0.2.2'
    row = select_target_cohort(flows, (2,)).iloc[0]
    assert row.context_source_ip == '192.0.2.3'
    assert row.context_source_basis == 'first_observed_src'
    assert row.initial_syn_sender_ip == '192.0.2.2'


@pytest.mark.parametrize('empty_input', [False, True])
def test_empty_cohort_has_exact_schema_and_empty_indexes(flows, empty_input):
    cohort = select_target_cohort(flows.iloc[:0] if empty_input else flows, (99,))
    assert cohort.empty
    assert list(cohort.columns) == EXPECTED_COLUMNS
    indexes = build_context_indexes(cohort)
    assert indexes.target_flow_by_key == {}
    assert indexes.candidate_source_ips == frozenset()


@pytest.mark.parametrize('counts', [(), (0,), (-1, 1), (1, 1, 2), (1.5,), (True,)])
def test_rejects_invalid_packet_counts(flows, counts):
    with pytest.raises(ValueError, match='packet_counts'):
        select_target_cohort(flows, counts)


def test_accepts_other_positive_unique_counts(flows):
    cohort = select_target_cohort(flows, (7, 4))
    assert cohort.target_flow_id.tolist() == [12, 15]
    assert cohort.observed_packet_count.tolist() == [4, 7]


def test_selection_does_not_mutate_input(flows):
    before = flows.copy(deep=True)
    cohort = select_target_cohort(flows, (1, 2, 3))
    cohort.iloc[0, cohort.columns.get_loc('src_ip')] = '192.0.2.99'
    pd.testing.assert_frame_equal(flows, before)


def test_indexes_include_all_flows_and_reverse_direction(flows):
    indexes = build_context_indexes(select_target_cohort(flows, (1, 2, 3)))
    assert indexes.target_flow_by_key == {
        FlowKey.from_packet('192.0.2.1', 1000, '192.0.2.2', 80, 6): 2,
        FlowKey.from_packet('192.0.2.1', 1001, '192.0.2.2', 80, 6): 7,
        FlowKey.from_packet('192.0.2.3', 1002, '192.0.2.2', 80, 17): 10,
    }
    reverse = FlowKey.from_packet('192.0.2.2', 80, '192.0.2.1', 1000, 6)
    assert indexes.target_flow_by_key[reverse] == 2


def test_candidate_sources_are_frozen_and_deduplicated(flows):
    flows.loc[9, 'initial_syn_sender_ip'] = '192.0.2.1'
    cohort = select_target_cohort(flows, (1, 2, 3))
    indexes = build_context_indexes(cohort)
    assert isinstance(indexes.candidate_source_ips, frozenset)
    assert indexes.candidate_source_ips == frozenset({'192.0.2.1', '192.0.2.3'})
    assert len(cohort) == 3
    assert len(indexes.candidate_source_ips) == 2


def test_conflicting_ids_for_same_bidirectional_key_fail(flows):
    cohort = select_target_cohort(flows, (1, 2, 3))
    duplicate = cohort.iloc[[0]].copy()
    duplicate['target_flow_id'] = 99
    duplicate[['src_ip', 'src_port', 'dst_ip', 'dst_port']] = [['192.0.2.2', 80, '192.0.2.1', 1000]]
    with pytest.raises(ValueError, match='FlowKey'):
        build_context_indexes(pd.concat([cohort, duplicate]))


def test_same_id_for_conflicting_flow_keys_fails(flows):
    cohort = select_target_cohort(flows, (1, 2, 3))
    cohort.iloc[1, cohort.columns.get_loc('target_flow_id')] = 2
    with pytest.raises(ValueError, match='target_flow_id'):
        build_context_indexes(cohort)


@pytest.mark.parametrize('column', ['flow_id', 'packet_count', 'start_time', 'initial_syn_sender_ip'])
def test_selection_rejects_missing_required_columns(flows, column):
    with pytest.raises(ValueError, match=column):
        select_target_cohort(flows.drop(columns=column), (1, 2, 3))


@pytest.mark.parametrize('column', ['target_flow_id', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'context_source_ip'])
def test_indexes_reject_missing_required_columns(flows, column):
    cohort = select_target_cohort(flows, (1, 2, 3)).drop(columns=column)
    with pytest.raises(ValueError, match=column):
        build_context_indexes(cohort)


def test_consumes_task_two_frame_with_ipv6(tmp_path):
    frame = packet(src='2001:db8::1', dst='2001:db8::2', protocol=17)
    parsed = parse_target_flows(write_capture(tmp_path/'target', [(20, frame, len(frame))]))
    cohort = select_target_cohort(parsed.frame, (1, 2, 3))
    assert cohort.target_flow_id.tolist() == [1]
    assert cohort.context_source_ip.tolist() == ['2001:db8::1']
    reverse = FlowKey.from_packet('2001:db8::2', 80, '2001:db8::1', 1234, 17)
    assert build_context_indexes(cohort).target_flow_by_key[reverse] == 1
