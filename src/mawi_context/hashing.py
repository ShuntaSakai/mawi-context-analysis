"""SHA-256 primitives for file bytes and canonical JSON representations."""
import hashlib
import json
from pathlib import Path


def sha256_file(path: Path) -> str:
    """Hash file bytes with fixed 1 MiB reads, without loading the whole file."""
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def stable_json_hash(value: object) -> str:
    """Hash sorted, compact, unescaped UTF-8 stdlib JSON, rejecting NaN/Inf.

    No custom serializer or repr fallback is used. Array order and stdlib
    number spelling (including the distinction between 1 and 1.0) remain
    significant; this is not a cross-language numeric canonicalization.
    """
    encoded = json.dumps(
        value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False,
    ).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()
