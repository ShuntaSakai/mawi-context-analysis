"""Shared cohort and lookups for packet counts observed in the target window."""
from dataclasses import dataclass

import pandas as pd

from mawi_context.flow import FlowKey


COHORT_COLUMNS = (
    'target_flow_id', 'observed_packet_count', 'ip_version', 'protocol',
    'src_ip', 'src_port', 'dst_ip', 'dst_port',
    'target_start_time', 'target_end_time', 'target_duration',
    'initial_syn_sender_ip', 'initial_syn_sender_port',
    'initial_syn_receiver_ip', 'initial_syn_receiver_port',
    'context_source_ip', 'context_source_basis',
)

_FLOW_RENAMES = {
    'flow_id': 'target_flow_id', 'packet_count': 'observed_packet_count',
    'start_time': 'target_start_time', 'end_time': 'target_end_time',
    'duration': 'target_duration',
}
_FLOW_COLUMNS = tuple(
    {target: source for source, target in _FLOW_RENAMES.items()}.get(column, column)
    for column in COHORT_COLUMNS[:-2]
)
_INDEX_COLUMNS = (
    'target_flow_id', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
    'protocol', 'context_source_ip',
)


def _require_columns(frame: pd.DataFrame, columns: tuple[str, ...]) -> None:
    missing = [column for column in columns if column not in frame.columns]
    if missing:
        raise ValueError(f'missing required columns: {", ".join(missing)}')


def select_target_cohort(
    flows: pd.DataFrame, packet_counts: tuple[int, ...],
) -> pd.DataFrame:
    """Select one shared cohort, preserving flow IDs and capture-first row order.

    Counts and target intervals describe only the target observation window,
    not the communication's full lifetime or true session boundaries. SYN
    metadata is consumed as an observed fact from Task 2, without decoding.
    """
    if (not packet_counts
            or any(not isinstance(count, int) or isinstance(count, bool) or count <= 0
                   for count in packet_counts)
            or len(set(packet_counts)) != len(packet_counts)):
        raise ValueError('packet_counts must contain unique positive integers')
    _require_columns(flows, _FLOW_COLUMNS)
    cohort = flows.loc[flows['packet_count'].isin(packet_counts), list(_FLOW_COLUMNS)].copy()
    cohort = cohort.rename(columns=_FLOW_RENAMES)
    use_syn = (cohort['protocol'] == 6) & cohort['initial_syn_sender_ip'].notna()
    cohort['context_source_ip'] = cohort['src_ip'].where(
        ~use_syn, cohort['initial_syn_sender_ip'],
    )
    cohort['context_source_basis'] = 'first_observed_src'
    cohort.loc[use_syn, 'context_source_basis'] = 'initial_syn_sender'
    return cohort.loc[:, list(COHORT_COLUMNS)]


@dataclass(frozen=True)
class ContextIndexes:
    """Lookup values for read-only use by later workers; no dataset state."""

    target_flow_by_key: dict[FlowKey, int]
    candidate_source_ips: frozenset[str]


def build_context_indexes(cohort: pd.DataFrame) -> ContextIndexes:
    """Build canonical bidirectional lookups, rejecting conflicting identities."""
    _require_columns(cohort, _INDEX_COLUMNS)
    target_flow_by_key: dict[FlowKey, int] = {}
    key_by_id: dict[int, FlowKey] = {}
    for row in cohort.loc[:, list(_INDEX_COLUMNS)].itertuples(index=False):
        key = FlowKey.from_packet(
            row.src_ip, row.src_port, row.dst_ip, row.dst_port, row.protocol,
        )
        if key in target_flow_by_key and target_flow_by_key[key] != row.target_flow_id:
            raise ValueError('conflicting target_flow_id values for the same FlowKey')
        if row.target_flow_id in key_by_id and key_by_id[row.target_flow_id] != key:
            raise ValueError('conflicting FlowKey values for the same target_flow_id')
        target_flow_by_key[key] = row.target_flow_id
        key_by_id[row.target_flow_id] = key
    return ContextIndexes(target_flow_by_key, frozenset(cohort['context_source_ip']))
