import pytest
from mawi_context.chunks import normalized_day, expected_chunk_ids, validate_target_chunk, render_ditl_chunk_url

@pytest.mark.parametrize('day', ['2026/04/08', '20260408', '2026-4-8', '2026-02-29', '2026-04-31', '', '2026-04-08\n'])
def test_invalid_day(day):
    with pytest.raises(ValueError): normalized_day(day)

@pytest.mark.parametrize('day', ['2026-04-08', '2024-02-29'])
def test_calendar_day(day):
    assert normalized_day(day) == day

def test_exact_plan():
    ids = expected_chunk_ids('2026-04-08')
    assert isinstance(ids, tuple) and len(ids) == len(set(ids)) == 96
    assert ids == tuple(f'20260408{h:02}{m:02}' for h in range(24) for m in (0,15,30,45))
    assert ids[0] == '202604080000' and ids[-1] == '202604082345'

@pytest.mark.parametrize('chunk', ['202604091400', '202604081401', '202604082400', 'bad', '20260408140'])
def test_invalid_target(chunk):
    with pytest.raises(ValueError): validate_target_chunk('2026-04-08', chunk)

def test_target_and_url():
    assert validate_target_chunk('2026-04-08', '202604081400') == '202604081400'
    assert render_ditl_chunk_url('2026-04-08', '202604081400') == 'https://mawi.nezu.wide.ad.jp/mawi/ditl/ditl2026/202604081400.pcap.gz'
    assert '/ditl2024/' in render_ditl_chunk_url('2024-02-29', '202402290000')
    with pytest.raises(ValueError): render_ditl_chunk_url('2026-04-08', '../bad')
