"""Transient owned capture downloads; no portable artifact paths."""
from dataclasses import asdict
from http.client import IncompleteRead
import math
import os
from pathlib import Path
import re
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from mawi_context.hashing import sha256_file
from mawi_context.manifests import load_json_object, write_json_atomically
from mawi_context.observations import RawSourceIdentity


def _paths(chunk_id: str, spool_root: Path) -> tuple[Path, Path, Path]:
    if not isinstance(chunk_id, str) or re.fullmatch('[0-9]{12}', chunk_id) is None:
        raise ValueError('chunk_id must be twelve digits')
    root = Path(spool_root)
    return (root/f'{chunk_id}.pcap.gz', root/f'{chunk_id}.download.json',
            root/f'{chunk_id}.pcap.gz.part')


def _owned_source(chunk_id: str, source_url: str, spool_root: Path) -> RawSourceIdentity | None:
    raw, metadata, _ = _paths(chunk_id, spool_root)
    if not os.path.lexists(raw) and not os.path.lexists(metadata):
        return None
    if (raw.is_symlink() or metadata.is_symlink() or not raw.is_file() or not metadata.is_file()):
        raise ValueError('raw capture requires regular matching ownership evidence')
    try:
        facts = load_json_object(metadata)
        if set(facts) != {'chunk_id', 'source_url', 'sha256', 'size_bytes'}:
            raise ValueError('invalid download metadata structure')
        source = RawSourceIdentity(**facts)
    except (ValueError, TypeError) as error:
        raise ValueError('invalid download metadata') from error
    if (source.chunk_id != chunk_id or source.source_url != source_url
            or raw.stat().st_size != source.size_bytes or sha256_file(raw) != source.sha256):
        raise ValueError('download ownership/bytes mismatch')
    return source


def _delete_owned_raw(source: RawSourceIdentity, spool_root: Path) -> None:
    # Called only by the parent after independently validating the published cache.
    if _owned_source(source.chunk_id, source.source_url, spool_root) != source:
        raise ValueError('refusing to delete mismatched raw capture')
    raw, metadata, _ = _paths(source.chunk_id, spool_root)
    raw.unlink()
    metadata.unlink()


def download_chunk(
    chunk_id: str, source_url: str, spool_root: Path, *, timeout: float = 60.0,
    retries: int = 3, backoff_seconds: float = 1.0,
) -> dict[str, object]:
    """Stream with at most retries attempts; reuse only verified owned bytes.

    Retry transport failures and HTTP 408/429/5xx, never identity conflicts or
    content validation errors. Interrupted publication fails closed on rerun.
    A spool is owned by one extraction parent at a time.
    """
    raw, metadata, part = _paths(chunk_id, spool_root)
    if not isinstance(source_url, str) or not source_url.strip():
        raise ValueError('source_url must be nonempty')
    if not isinstance(retries, int) or isinstance(retries, bool) or retries <= 0:
        raise ValueError('retries must be a positive integer attempt limit')
    for value, positive in ((timeout, True), (backoff_seconds, False)):
        if (not isinstance(value, (int, float)) or isinstance(value, bool)
                or not math.isfinite(value) or value < 0 or (positive and value == 0)):
            raise ValueError('timeout/backoff must be finite and in range')
    existing = _owned_source(chunk_id, source_url, Path(spool_root))
    if existing is not None:
        return asdict(existing)
    raw.parent.mkdir(parents=True, exist_ok=True)
    if part.is_symlink() or (os.path.lexists(part) and not part.is_file()):
        raise ValueError('partial must be a regular file')
    part.unlink(missing_ok=True)
    for attempt in range(retries):
        try:
            with part.open('xb') as output:
                with urlopen(source_url, timeout=timeout) as response:
                    length = response.headers.get('Content-Length')
                    size = 0
                    while block := response.read(1024 * 1024):
                        output.write(block)
                        size += len(block)
                    if length is not None and size != int(length):
                        raise ValueError('Content-Length mismatch')
                output.flush()
                os.fsync(output.fileno())
            source = RawSourceIdentity(chunk_id, source_url, sha256_file(part), part.stat().st_size)
            # Atomic no-replacement publication. link avoids replacing an unknown
            # destination if it appeared since the ownership check.
            os.link(part, raw)
            part.unlink()
            write_json_atomically(metadata, asdict(source))
            return asdict(source)
        except (URLError, TimeoutError, ConnectionError, IncompleteRead) as error:
            if isinstance(error, HTTPError) and error.code not in (408, 429) and error.code < 500:
                raise
            if attempt + 1 == retries:
                raise
            time.sleep(backoff_seconds * (2 ** attempt))
        finally:
            part.unlink(missing_ok=True)
    raise AssertionError('unreachable')
