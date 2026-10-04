from io import BytesIO
import hashlib
import json
from urllib.error import URLError, HTTPError
import pytest
import mawi_context.downloader as dl

CHUNK = '202604081400'
URL = 'https://example.test/raw'
BODY = b'raw capture bytes'

class Response(BytesIO):
    def __init__(self, body=BODY, length=None):
        super().__init__(body)
        self.headers = {} if length is None else {'Content-Length': str(length)}

@pytest.fixture
def network(monkeypatch, tmp_path):
    calls = []
    def opener(url, timeout):
        calls.append((url, timeout))
        assert (tmp_path/f'{CHUNK}.pcap.gz.part').exists()
        assert not (tmp_path/f'{CHUNK}.pcap.gz').exists()
        return Response(length=len(BODY))
    monkeypatch.setattr(dl, 'urlopen', opener)
    return calls

def test_stream_publication_and_reuse(tmp_path, network):
    facts = dl.download_chunk(CHUNK, URL, tmp_path)
    expected = dict(chunk_id=CHUNK, source_url=URL, sha256=hashlib.sha256(BODY).hexdigest(), size_bytes=len(BODY))
    assert facts == expected
    assert json.loads((tmp_path/f'{CHUNK}.download.json').read_text()) == expected
    assert (tmp_path/f'{CHUNK}.pcap.gz').read_bytes() == BODY
    assert not (tmp_path/f'{CHUNK}.pcap.gz.part').exists()
    assert dl.download_chunk(CHUNK, URL, tmp_path) == expected
    assert network == [(URL, 60.0)]

@pytest.mark.parametrize('damage', ['checksum', 'size', 'url', 'malformed', 'unowned', 'metadata-only'])
def test_rejects_unowned_or_conflicting_files(tmp_path, network, damage):
    dl.download_chunk(CHUNK, URL, tmp_path)
    raw, meta = tmp_path/f'{CHUNK}.pcap.gz', tmp_path/f'{CHUNK}.download.json'
    if damage == 'checksum': raw.write_bytes(b'x'*len(BODY))
    elif damage == 'size': raw.write_bytes(b'x')
    elif damage == 'url':
        value = json.loads(meta.read_text()); value['source_url'] = 'other'; meta.write_text(json.dumps(value))
    elif damage == 'malformed': meta.write_text('{')
    elif damage == 'unowned': meta.unlink()
    else: raw.unlink()
    before = {p.name:p.read_bytes() for p in tmp_path.iterdir()}
    with pytest.raises(ValueError): dl.download_chunk(CHUNK, URL, tmp_path)
    assert before == {p.name:p.read_bytes() for p in tmp_path.iterdir()}
    assert len(network) == 1

def test_length_mismatch_no_completed_files(tmp_path, monkeypatch):
    monkeypatch.setattr(dl, 'urlopen', lambda *a, **kw: Response(length=999))
    with pytest.raises(ValueError, match='Content-Length'): dl.download_chunk(CHUNK, URL, tmp_path)
    assert list(tmp_path.iterdir()) == []

def test_bounded_retry_and_cleanup(tmp_path, monkeypatch):
    calls = []
    def fail(*a, **kw):
        calls.append(1); raise URLError('temporary')
    monkeypatch.setattr(dl, 'urlopen', fail)
    monkeypatch.setattr(dl.time, 'sleep', lambda _: None)
    with pytest.raises(URLError): dl.download_chunk(CHUNK, URL, tmp_path, retries=3)
    assert len(calls) == 3 and list(tmp_path.iterdir()) == []

def test_retry_success_and_stale_partial(tmp_path, monkeypatch):
    part = tmp_path/f'{CHUNK}.pcap.gz.part'; part.write_bytes(b'stale')
    calls = []
    def open_response(*a, **kw):
        calls.append(1)
        if len(calls) == 1: raise URLError('temporary')
        return Response()
    monkeypatch.setattr(dl, 'urlopen', open_response)
    dl.download_chunk(CHUNK, URL, tmp_path, backoff_seconds=0)
    assert len(calls) == 2 and not part.exists()

def test_permanent_http_failure_not_retried(tmp_path, monkeypatch):
    calls = []
    def fail(*a, **kw):
        calls.append(1); raise HTTPError(URL, 404, 'missing', {}, None)
    monkeypatch.setattr(dl, 'urlopen', fail)
    with pytest.raises(HTTPError): dl.download_chunk(CHUNK, URL, tmp_path)
    assert len(calls) == 1

@pytest.mark.parametrize('kwargs', [{'retries':0},{'retries':True},{'retries':1.5},{'timeout':0},{'timeout':float('nan')},{'timeout':True},{'backoff_seconds':-1},{'backoff_seconds':float('inf')}])
def test_invalid_options(tmp_path, kwargs):
    with pytest.raises(ValueError): dl.download_chunk(CHUNK, URL, tmp_path, **kwargs)


def test_interrupted_stream_retries_and_cleans_partial(tmp_path,monkeypatch):
    from http.client import IncompleteRead
    calls=[]
    class Broken(Response):
        def read(self,size=-1):raise IncompleteRead(b'partial',len(BODY))
    def opener(*a,**kw):
        calls.append(1)
        return Broken() if len(calls)==1 else Response(length=len(BODY))
    monkeypatch.setattr(dl,'urlopen',opener)
    facts=dl.download_chunk(CHUNK,URL,tmp_path,backoff_seconds=0)
    assert facts['sha256']==hashlib.sha256(BODY).hexdigest()
    assert len(calls)==2 and not (tmp_path/f'{CHUNK}.pcap.gz.part').exists()


def test_raw_deletion_revalidates_ownership(tmp_path,network):
    from mawi_context.observations import RawSourceIdentity
    source=RawSourceIdentity(**dl.download_chunk(CHUNK,URL,tmp_path))
    raw=tmp_path/f'{CHUNK}.pcap.gz';meta=tmp_path/f'{CHUNK}.download.json'
    raw.write_bytes(b'x'*len(BODY))
    with pytest.raises(ValueError):dl._delete_owned_raw(source,tmp_path)
    assert raw.exists() and meta.exists()
