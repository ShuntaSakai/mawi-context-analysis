"""Calendar-day planning for 96 independent quarter-hour DITL captures."""
from datetime import date
import re


def normalized_day(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', value) is None:
        raise ValueError('day must be YYYY-MM-DD')
    return date.fromisoformat(value).isoformat()


def expected_chunk_ids(day: str) -> tuple[str, ...]:
    prefix = normalized_day(day).replace('-', '')
    return tuple(f'{prefix}{hour:02}{minute:02}'
                 for hour in range(24) for minute in (0, 15, 30, 45))


def validate_target_chunk(day: str, chunk_id: str) -> str:
    if chunk_id not in expected_chunk_ids(day):
        raise ValueError('target chunk must belong to day on a quarter-hour boundary')
    return chunk_id


def render_ditl_chunk_url(day: str, chunk_id: str) -> str:
    day = normalized_day(day)
    chunk = validate_target_chunk(day, chunk_id)
    return f'https://mawi.nezu.wide.ad.jp/mawi/ditl/ditl{day[:4]}/{chunk}.pcap.gz'
