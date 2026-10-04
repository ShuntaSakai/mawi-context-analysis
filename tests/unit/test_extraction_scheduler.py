from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
import threading
import time
import pytest
import mawi_context.extraction as ex
from mawi_context.observations import RawSourceIdentity

DAY = '2026-04-08'
TARGET = '202604080000'

def options(tmp_path, workers=2):
    return ex.ExtractOptions(DAY, TARGET, (3,1,2), workers, tmp_path/'dataset', tmp_path/'spool')

@pytest.mark.parametrize('change', [dict(day='2026-4-8'),dict(target_chunk='202604080001'),dict(packet_counts=()),dict(packet_counts=(True,)),dict(packet_counts=(1,1)),dict(packet_counts=(0,)),dict(packet_counts=(1.5,)),dict(workers=0),dict(workers=True),dict(dataset_root=None)])
def test_options_validate(tmp_path, change):
    kw = dict(day=DAY,target_chunk=TARGET,packet_counts=(1,),workers=2,dataset_root=tmp_path/'d',spool_root=tmp_path/'s'); kw.update(change)
    with pytest.raises((ValueError, TypeError)): ex.ExtractOptions(**kw)

def test_other_counts_and_paths(tmp_path):
    o = ex.ExtractOptions(DAY,TARGET,(7,4),1,str(tmp_path/'d'),str(tmp_path/'s'))
    assert o.packet_counts == (4,7) and isinstance(o.dataset_root, Path)

@pytest.mark.parametrize('failure', ['none', 'download', 'scan', 'cache'])
def test_bounded_pipeline_overlap_continuation_and_reuse(tmp_path, monkeypatch, failure):
    o = options(tmp_path)
    ids = ex.expected_chunk_ids(DAY)
    state = {c:dict(status='pending') for c in ids}
    lock = threading.Lock(); active = dict(download=0,scan=0); maxima = active.copy()
    downloaded=[]; scanned=[]; finished=[]; overlapping=[]; outstanding=[]
    source = lambda c: RawSourceIdentity(c, 'https://example/'+c, 'a'*64, 5)
    reused = ids[1]
    def cache(root,c,**kwargs):
        if c == reused: return dict(source=asdict(source(c)))
        raise ValueError('invalid')
    final = o.dataset_root/'observations'/reused; final.mkdir(parents=True)
    if failure == 'cache': (o.dataset_root/'observations'/ids[2]).mkdir()
    monkeypatch.setattr(ex, 'load_validated_chunk', cache)
    monkeypatch.setattr(ex, '_owned_source', lambda *a: None)
    def download(c,url,root):
        with lock:
            active['download']+=1; maxima['download']=max(maxima['download'],active['download']); downloaded.append(c)
            outstanding.append(len(downloaded)-len(finished))
        time.sleep(.003)
        with lock: active['download']-=1
        if failure=='download' and c==ids[2]: raise OSError('/private/secret/path')
        return asdict(source(c))
    def scan(task):
        with lock:
            active['scan']+=1; maxima['scan']=max(maxima['scan'],active['scan']); scanned.append(task.chunk_id)
            overlapping.append(active['download']>0)
        time.sleep(.01)
        with lock: active['scan']-=1
        if failure=='scan' and task.chunk_id==ids[2]: raise ValueError('scan')
        return ex.ScanChunkResult(task.chunk_id,task.staging,task.source,task.cohort_identity)
    def finish(task,result,o):
        assert result.chunk_id == task.chunk_id
        finished.append(task.chunk_id)
        return {'source':asdict(task.source)}
    monkeypatch.setattr(ex,'download_chunk',download)
    monkeypatch.setattr(ex,'_scan_chunk_worker',scan)
    monkeypatch.setattr(ex,'_finish_chunk',finish)
    with ThreadPoolExecutor(max_workers=2) as downloads, ThreadPoolExecutor(max_workers=o.workers) as scans:
        ex._schedule_chunks(o,ids,'b'*64,state,lambda:None,lambda day,c:'https://example/'+c,downloads,scans)
    assert maxima == dict(download=2,scan=2)
    assert any(overlapping) and max(outstanding) <= o.workers+3
    assert reused not in downloaded and reused not in scanned
    assert state[ids[-1]]['status']=='success'
    assert len(scanned)==len(set(scanned))
    if failure!='none':
        assert state[ids[2]]['status']=='failed'
        assert '/private/' not in str(state)
    else: assert all(s['status']=='success' for s in state.values())

@pytest.mark.parametrize('phase', ['result','staging','reload','success'])
def test_parent_validation_publication_deletion_order(tmp_path, monkeypatch, phase):
    o=options(tmp_path); o.dataset_root.mkdir()
    stage=o.dataset_root/'.staging-test'; stage.mkdir(); (stage/'evidence').write_text('bytes')
    source=RawSourceIdentity(TARGET,'url','a'*64,1)
    task=ex.ScanChunkTask(TARGET,tmp_path/'raw',stage,o.dataset_root,source,'b'*64)
    result=ex.ScanChunkResult(TARGET,stage,source,'b'*64)
    if phase=='result': result=ex.ScanChunkResult('other',stage,source,'b'*64)
    events=[]
    def validate(*a,**kw):
        events.append('staged')
        if phase=='staging': raise ValueError('invalid staged')
    def reload(*a,**kw):
        events.append('reload')
        if phase=='reload': raise ValueError('invalid final')
        return dict(source=asdict(source))
    def delete(*a): events.append('delete')
    monkeypatch.setattr(ex.obs,'_validate_chunk',validate)
    monkeypatch.setattr(ex,'load_validated_chunk',reload)
    monkeypatch.setattr(ex,'_delete_owned_raw',delete)
    if phase=='success':
        ex._finish_chunk(task,result,o)
        assert events==['staged','reload','delete']
    else:
        with pytest.raises(ValueError): ex._finish_chunk(task,result,o)
        assert 'delete' not in events
        assert not (o.dataset_root/'observations'/TARGET).exists()


def test_progress_source_identity_cannot_be_replaced(tmp_path, monkeypatch):
    o=options(tmp_path); c=TARGET
    states={c:dict(status='pending',source=asdict(RawSourceIdentity(c,'url','a'*64,1)))}
    monkeypatch.setattr(ex,'_owned_source',lambda *a:None)
    monkeypatch.setattr(ex,'download_chunk',lambda *a:asdict(RawSourceIdentity(c,'url','b'*64,1)))
    scans=[]
    monkeypatch.setattr(ex,'_scan_chunk_worker',lambda task:scans.append(task))
    with ThreadPoolExecutor(max_workers=2) as d, ThreadPoolExecutor(max_workers=2) as s:
        ex._schedule_chunks(o,(c,),'c'*64,states,lambda:None,lambda *a:'url',d,s)
    assert states[c]['status']=='failed'
    assert states[c]['source']['sha256']=='a'*64 and scans==[]


def test_owned_raw_bypasses_downloader(tmp_path, monkeypatch):
    o=options(tmp_path); source=RawSourceIdentity(TARGET,'url','a'*64,1)
    state={TARGET:dict(status='pending')}
    monkeypatch.setattr(ex,'_owned_source',lambda *a:source)
    monkeypatch.setattr(ex,'download_chunk',lambda *a:pytest.fail('owned raw needs no download'))
    monkeypatch.setattr(ex,'_scan_chunk_worker',lambda t:ex.ScanChunkResult(t.chunk_id,t.staging,t.source,t.cohort_identity))
    monkeypatch.setattr(ex,'_finish_chunk',lambda t,r,o:dict(source=asdict(t.source)))
    with ThreadPoolExecutor(max_workers=2) as d, ThreadPoolExecutor(max_workers=2) as s:
        ex._schedule_chunks(o,(TARGET,),'b'*64,state,lambda:None,lambda *a:'url',d,s)
    assert state[TARGET]['status']=='success'


def test_staging_creation_failure_continues_siblings(tmp_path,monkeypatch):
    o=options(tmp_path); ids=ex.expected_chunk_ids(DAY)[:2]
    states={c:dict(status='pending') for c in ids}
    monkeypatch.setattr(ex,'_owned_source',lambda c,*a:RawSourceIdentity(c,'url','a'*64,1))
    original=ex.tempfile.mkdtemp;failed=False
    def staging(*a,**kw):
        nonlocal failed
        if not failed:failed=True;raise OSError('staging failure')
        return original(*a,**kw)
    monkeypatch.setattr(ex.tempfile,'mkdtemp',staging)
    monkeypatch.setattr(ex,'_scan_chunk_worker',lambda t:ex.ScanChunkResult(t.chunk_id,t.staging,t.source,t.cohort_identity))
    monkeypatch.setattr(ex,'_finish_chunk',lambda t,r,o:dict(source=asdict(t.source)))
    with ThreadPoolExecutor(max_workers=2) as d, ThreadPoolExecutor(max_workers=2) as s:
        ex._schedule_chunks(o,ids,'b'*64,states,lambda:None,lambda *a:'url',d,s)
    assert states[ids[0]]['status']=='failed' and states[ids[1]]['status']=='success'


def test_csv_row_count_requires_integer_not_bool(tmp_path):
    import pandas as pd
    root=tmp_path/'dataset';root.mkdir();p=root/'small.csv'
    pd.DataFrame({'flow_id':[1]}).to_csv(p,index=False)
    record=ex.artifact_record(root,p,row_count=1,schema_version='small-v1');record['row_count']=True
    with pytest.raises(ValueError):ex._validated_csv(root,'small.csv',('flow_id',),'small-v1',record)
