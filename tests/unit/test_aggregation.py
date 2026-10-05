"""Interval and source statistics with synthetic SQLite observations."""
import sqlite3

import pytest

from mawi_context import aggregation as ag


EXPECTED_COLUMNS = tuple('''
target_flow_id observed_packet_count ip_version protocol src_ip src_port dst_ip dst_port
target_start_time target_end_time target_duration context_source_ip context_source_basis
same_tuple_packet_count_24h same_tuple_before_count same_tuple_target_interval_count same_tuple_after_count
previous_same_tuple_timestamp previous_same_tuple_gap_seconds next_same_tuple_timestamp next_same_tuple_gap_seconds
same_tuple_before_1s_count same_tuple_after_1s_count same_tuple_before_10s_count same_tuple_after_10s_count
same_tuple_before_60s_count same_tuple_after_60s_count same_tuple_before_300s_count same_tuple_after_300s_count
tcp_control_packet_count_24h tcp_outbound_plain_syn_count_24h tcp_inbound_syn_ack_count_24h
tcp_outbound_rst_count_24h tcp_inbound_rst_count_24h tcp_outbound_fin_count_24h tcp_inbound_fin_count_24h
tcp_outbound_unique_dst_ip_count_24h tcp_outbound_unique_dst_port_count_24h tcp_outbound_unique_dst_ip_port_count_24h
tcp_control_packet_count_window_60s tcp_outbound_plain_syn_count_window_60s tcp_inbound_syn_ack_count_window_60s
tcp_outbound_rst_count_window_60s tcp_inbound_rst_count_window_60s tcp_outbound_fin_count_window_60s tcp_inbound_fin_count_window_60s
tcp_outbound_unique_dst_ip_count_window_60s tcp_outbound_unique_dst_port_count_window_60s tcp_outbound_unique_dst_ip_port_count_window_60s
tcp_control_packet_count_window_300s tcp_outbound_plain_syn_count_window_300s tcp_inbound_syn_ack_count_window_300s
tcp_outbound_rst_count_window_300s tcp_inbound_rst_count_window_300s tcp_outbound_fin_count_window_300s tcp_inbound_fin_count_window_300s
tcp_outbound_unique_dst_ip_count_window_300s tcp_outbound_unique_dst_port_count_window_300s tcp_outbound_unique_dst_ip_port_count_window_300s
udp_outbound_packet_count_24h udp_outbound_unique_dst_ip_count_24h udp_outbound_unique_dst_port_count_24h udp_outbound_unique_dst_ip_port_count_24h
udp_outbound_packet_count_window_60s udp_outbound_unique_dst_ip_count_window_60s udp_outbound_unique_dst_port_count_window_60s udp_outbound_unique_dst_ip_port_count_window_60s
udp_outbound_packet_count_window_300s udp_outbound_unique_dst_ip_count_window_300s udp_outbound_unique_dst_port_count_window_300s udp_outbound_unique_dst_ip_port_count_window_300s
'''.split())
BANNED = {'scan', 'scan_like', 'scanner', 'malicious', 'benign', 'attack', 'anomaly',
          'successful_connection', 'failed_connection', 'client', 'server', 'attacker', 'victim'}
A, B, C = '2001:db8::1', '2001:db8::2', '2001:db8::3'


def test_exact_result_schema():
    assert ag.CONTEXT_RESULT_COLUMNS == EXPECTED_COLUMNS
    assert len(EXPECTED_COLUMNS) == 71
    assert not BANNED.intersection(EXPECTED_COLUMNS)


def cohort_row(flow_id=1, count=1, protocol=6, start=1000.125, end=None):
    end = start if end is None else end
    return (flow_id, count, 6, protocol, A, 1000+flow_id, B, 80,
            start, end, end-start, A, 'first_observed_src')


def metrics(cohorts, targets=(), sources=()):
    with sqlite3.connect(':memory:') as db:
        ag._create_tables(db)
        db.executemany('INSERT INTO cohort VALUES ('+','.join('?'*13)+')', cohorts)
        db.executemany('INSERT INTO target VALUES (?,?)', targets)
        db.executemany('INSERT INTO source VALUES (?,?,?,?,?,?,?)', sources)
        ag._compute_metrics(db)
        return {r[0]: dict(zip(EXPECTED_COLUMNS, r)) for r in ag._result_rows(db)}


@pytest.mark.parametrize('count', [1, 2, 3])
def test_target_partition_previous_next_and_all_boundaries(count):
    s = 1000.125
    e = s+count-1
    before = [s-301, s-300, s-60, s-10, s-1, s-.5]
    interval = [s+i for i in range(count)]
    after = [e+.5, e+1, e+10, e+60, e+300, e+301]
    row = metrics([cohort_row(count=count, start=s, end=e)],
                  [(1,t) for t in before+interval+after])[1]
    assert row['same_tuple_packet_count_24h'] == 12+count
    assert row['same_tuple_before_count'] == row['same_tuple_after_count'] == 6
    assert row['same_tuple_target_interval_count'] == count
    assert sum(row[c] for c in ('same_tuple_before_count', 'same_tuple_target_interval_count',
                                'same_tuple_after_count')) == row['same_tuple_packet_count_24h']
    assert row['previous_same_tuple_timestamp'] == s-.5
    assert row['previous_same_tuple_gap_seconds'] == .5
    assert row['next_same_tuple_timestamp'] == e+.5
    assert row['next_same_tuple_gap_seconds'] == .5
    for n, want in [(1,2), (10,3), (60,4), (300,5)]:
        assert row[f'same_tuple_before_{n}s_count'] == want
        assert row[f'same_tuple_after_{n}s_count'] == want


@pytest.mark.parametrize('times,previous,next_', [([1000.125],None,None),
    ([999.125,1000.125],999.125,None), ([1000.125,1001.125],None,1001.125), ([],None,None)])
def test_absent_neighbors_are_null(times, previous, next_):
    row = metrics([cohort_row()], [(1,t) for t in times])[1]
    assert row['previous_same_tuple_timestamp'] == previous
    assert row['next_same_tuple_timestamp'] == next_
    assert row['previous_same_tuple_gap_seconds'] == (None if previous is None else 1)
    assert row['next_same_tuple_gap_seconds'] == (None if next_ is None else 1)


def source(t, flags=2, src=A, dst=B, port=80, protocol=6):
    return (t,protocol,src,1234,dst,port,flags if protocol==6 else None)


def test_tcp_flags_directions_uniques_and_inclusive_windows():
    s,e = 1000.125,1002.125
    rows = [source(s-60), source(e+60,18,src=B,dst=A),
            source(s,4), source(s,4,src=B,dst=A),
            source(e,1,dst=C,port=443), source(e,1,src=C,dst=A),
            source(s-300,dst=B,port=443), source(e+300,dst=C,port=80),
            source(s-300.5,dst=C,port=443), source(e+300.5,18,src=C,dst=A),
            source(s,src=B,dst=C), source(s,protocol=17)]
    row = metrics([cohort_row(count=3,start=s,end=e)], sources=rows)[1]
    for horizon,total,syn,ack,ips,ports,pairs in [('24h',10,4,2,2,2,4),
            ('window_60s',6,1,1,2,2,2), ('window_300s',8,3,1,2,2,4)]:
        assert row[f'tcp_control_packet_count_{horizon}'] == total
        assert row[f'tcp_outbound_plain_syn_count_{horizon}'] == syn
        assert row[f'tcp_inbound_syn_ack_count_{horizon}'] == ack
        for direction in ('outbound','inbound'):
            for flag in ('rst','fin'):
                assert row[f'tcp_{direction}_{flag}_count_{horizon}'] == 1
        for kind,want in [('ip',ips),('port',ports),('ip_port',pairs)]:
            assert row[f'tcp_outbound_unique_dst_{kind}_count_{horizon}'] == want
    assert all(row[c] == 0 for c in EXPECTED_COLUMNS if c.startswith('udp_'))


def test_shared_source_has_flow_specific_windows_and_self_endpoint_is_counted_once():
    rows = [source(1000.125),source(2000.125),source(1000.125,src=A,dst=A)]
    result = metrics([cohort_row(),cohort_row(flow_id=2,start=2000.125)],sources=rows)
    assert result[1]['tcp_control_packet_count_24h'] == result[2]['tcp_control_packet_count_24h'] == 3
    assert result[1]['tcp_control_packet_count_window_60s'] == 2
    assert result[2]['tcp_control_packet_count_window_60s'] == 1


def test_udp_outbound_only_uniques_and_inclusive_windows():
    s,e=1000.125,1001.125
    rows=[source(s-60,protocol=17),source(e+60,dst=C,port=443,protocol=17),
          source(s-300,port=443,protocol=17),source(e+300,dst=C,protocol=17),
          source(s-301,protocol=17),source(e+301,protocol=17),
          source(s,src=B,dst=A,protocol=17),source(s)]
    row=metrics([cohort_row(protocol=17,count=2,start=s,end=e)],sources=rows)[1]
    for horizon,total,pairs in [('24h',6,4),('window_60s',2,2),('window_300s',4,4)]:
        assert row[f'udp_outbound_packet_count_{horizon}'] == total
        assert row[f'udp_outbound_unique_dst_ip_count_{horizon}'] == 2
        assert row[f'udp_outbound_unique_dst_port_count_{horizon}'] == 2
        assert row[f'udp_outbound_unique_dst_ip_port_count_{horizon}'] == pairs
    assert all(row[c] == 0 for c in EXPECTED_COLUMNS if c.startswith('tcp_'))


def test_multiple_bits_and_ack_relative_to_source():
    row=metrics([cohort_row()],sources=[
        source(1000.125,18), source(1000.125,2,src=B,dst=A),
        source(1000.125,7), source(1000.125,21,src=B,dst=A),
    ])[1]
    assert row['tcp_control_packet_count_24h']==4
    assert row['tcp_outbound_plain_syn_count_24h']==1
    assert row['tcp_inbound_syn_ack_count_24h']==0
    assert row['tcp_outbound_rst_count_24h']==row['tcp_outbound_fin_count_24h']==1
    assert row['tcp_inbound_rst_count_24h']==row['tcp_inbound_fin_count_24h']==1


def test_result_rows_sort_by_id_and_filter_count():
    with sqlite3.connect(':memory:') as db:
        ag._create_tables(db)
        db.executemany('INSERT INTO cohort VALUES ('+','.join('?'*13)+')',
            [cohort_row(flow_id=9),cohort_row(flow_id=2),cohort_row(flow_id=5,count=2)])
        ag._compute_metrics(db)
        assert [r[0] for r in ag._result_rows(db)]==[2,5,9]
        assert [r[0] for r in ag._result_rows(db,1)]==[2,9]
        assert list(ag._result_rows(db,99))==[]
