from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import asdict
import json
import multiprocessing
import os
from pathlib import Path
import sys
import threading
import time

import pandas as pd
import pytest
import mawi_context.extraction as ex
import mawi_context.downloader as dl
from mawi_context.cohort import COHORT_COLUMNS
from mawi_context.flow import FLOW_COLUMNS
from mawi_context.manifests import load_json_object, write_json_atomically
from mawi_context.hashing import sha256_file

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'helpers'))
from pcap_factory import packet, pcap_bytes
from io import BytesIO

DAY='2026-04-08'; IDS=ex.expected_chunk_ids(DAY)[:4]; TARGET=IDS[0]

@pytest.fixture
def setup(tmp_path, monkeypatch):
    o=ex.ExtractOptions(DAY,TARGET,(3,1,2),2,tmp_path/'dataset',tmp_path/'spool')
    frames=[packet(), packet(src='2001:db8::1',dst='2001:db8::2',protocol=17)]
    body=pcap_bytes([(1,frames[0],len(frames[0])),(2,frames[1],len(frames[1]))])
    calls=[]
    class Response(BytesIO):
        headers={}
    def opener(url,timeout):
        calls.append(url.rsplit('/',1)[-1]); return Response(body)
    monkeypatch.setattr(dl,'urlopen',opener)
    monkeypatch.setattr(ex,'expected_chunk_ids',lambda day: IDS)
    return o,calls


def resolver(day, chunk): return 'https://fixture.test/'+chunk


def test_four_chunk_failure_resume_and_portable_provenance(setup,monkeypatch):
    o,downloads=setup
    monkeypatch.setattr(ex,'ProcessPoolExecutor',ThreadPoolExecutor)
    scan=ex._scan_chunk_worker; scanned=[]; spans=[]; lock=threading.Lock(); fail=True
    def worker(task):
        start=time.monotonic()
        with lock: scanned.append(task.chunk_id)
        assert not (o.dataset_root/'observations'/task.chunk_id).exists()
        assert task.capture_path.exists()
        before=(o.dataset_root/'dataset_manifest.json').read_bytes()
        time.sleep(.04)
        if fail and task.chunk_id==IDS[1]: raise ValueError('/private/secret/raw')
        result=scan(task)
        with lock: spans.append((start,time.monotonic()))
        # Worker returns staging; publication and deletion have not happened.
        assert task.staging.is_dir() and task.capture_path.is_file()
        return result
    monkeypatch.setattr(ex,'_scan_chunk_worker',worker)
    with pytest.raises(ex.IncompleteExtractionError):
        ex.run_extract(o,source_url_resolver=resolver)
    path=o.dataset_root/'dataset_manifest.json'
    manifest=load_json_object(path)
    assert path==o.dataset_root/'dataset_manifest.json'
    assert downloads[0]==TARGET and downloads.count(TARGET)==1
    assert manifest['status']=='incomplete'
    assert manifest['expected_chunk_ids']==list(IDS)
    assert manifest['chunks'][IDS[1]]['status']=='failed'
    assert '/private/' not in json.dumps(manifest)
    assert (o.spool_root/f'{IDS[1]}.pcap.gz').exists()
    assert (o.spool_root/f'{IDS[1]}.download.json').exists()
    assert not (o.dataset_root/'observations'/IDS[1]).exists()
    for c in (IDS[0],IDS[2],IDS[3]):
        assert (o.dataset_root/'observations'/c/'manifest.json').is_file()
        assert not (o.spool_root/f'{c}.pcap.gz').exists()
        assert not (o.spool_root/f'{c}.download.json').exists()
    assert any(a[0]<b[1] and b[0]<a[1] for i,a in enumerate(spans) for b in spans[i+1:])
    for filename,columns in [('provenance/flows.csv',FLOW_COLUMNS),('cohort/target_cohort.csv',COHORT_COLUMNS)]:
        assert tuple(pd.read_csv(o.dataset_root/filename).columns)==columns
    fm=load_json_object(o.dataset_root/'provenance/flow_manifest.json')
    cm=load_json_object(o.dataset_root/'cohort/cohort_manifest.json')
    assert fm['manifest_schema_version']=='flow-manifest-v1'
    assert fm['flow_definition']==ex.FLOW_DEFINITION
    assert fm['source']['chunk_id']==TARGET
    assert cm['manifest_schema_version']=='cohort-manifest-v1'
    assert cm['context_source_policy']==ex.CONTEXT_SOURCE_POLICY
    assert cm['packet_counts']==[1,2,3]
    assert manifest['tool']==ex.TOOL_IDENTITY
    before={f:f.read_bytes() for d in ('provenance','cohort') for f in (o.dataset_root/d).iterdir()}
    fail=False; scanned.clear(); downloads.clear()
    assert ex.run_extract(o,source_url_resolver=resolver)==o.dataset_root
    complete=load_json_object(path)
    assert complete['status']=='success'
    assert scanned==[IDS[1]] and downloads==[]
    assert complete['cohort_identity']==manifest['cohort_identity']
    assert all(p.read_bytes()==content for p,content in before.items())
    for p in o.dataset_root.rglob('*.json'):
        assert str(o.spool_root) not in p.read_text()
        assert str(o.dataset_root) not in p.read_text()
        assert '.staging-' not in p.read_text()
    monkeypatch.setattr(ex,'download_chunk',lambda *a:pytest.fail('all caches reusable'))
    monkeypatch.setattr(ex,'_scan_chunk_worker',lambda *a:pytest.fail('all caches reusable'))
    ex.run_extract(o,source_url_resolver=resolver)


def timed_scan(task):
    start=time.monotonic(); time.sleep(.3)
    result=ex._scan_chunk_worker(task)
    return result,start,time.monotonic(),os.getpid()


def test_spawn_workers_initialized_and_overlap(setup):
    o,calls=setup
    # Target provenance is created by the actual process orchestration first.
    ex.run_extract(o,source_url_resolver=resolver)
    cm=load_json_object(o.dataset_root/'cohort/cohort_manifest.json')
    tasks=[]
    for c in IDS[:2]:
        source=ex.RawSourceIdentity(**dl.download_chunk(c,resolver(DAY,c),o.spool_root))
        stage=o.dataset_root/f'.staging-spawn-{c}';stage.mkdir()
        tasks.append(ex.ScanChunkTask(c,dl._paths(c,o.spool_root)[0],stage,o.dataset_root,source,cm['cohort_identity']))
    with ProcessPoolExecutor(max_workers=2,mp_context=multiprocessing.get_context('spawn'),initializer=ex._initialize_scan_worker,initargs=(str(o.dataset_root/'cohort/target_cohort.csv'),)) as pool:
        futures=[pool.submit(timed_scan,t) for t in tasks]
        results=[f.result() for f in futures]
    assert results[0][3]!=results[1][3]
    assert results[0][1]<results[1][2] and results[1][1]<results[0][2]
    for task,(result,*_) in zip(tasks,results):
        assert task.capture_path.exists()
        ex.obs._validate_chunk(o.dataset_root,task.staging,task.chunk_id,expected_cohort_identity=cm['cohort_identity'],expected_source=task.source)

@pytest.mark.parametrize('damage', ['csv','columns','row_count','version','counts','policy','source','dataset','cohort-id'])
def test_corrupt_provenance_fails_without_overwrite(setup,monkeypatch,damage):
    o,calls=setup; monkeypatch.setattr(ex,'ProcessPoolExecutor',ThreadPoolExecutor)
    ex.run_extract(o,source_url_resolver=resolver)
    flow=o.dataset_root/'provenance/flow_manifest.json'; cohort=o.dataset_root/'cohort/cohort_manifest.json'
    fm=load_json_object(flow); cm=load_json_object(cohort)
    csv=o.dataset_root/'provenance/flows.csv'
    if damage=='csv': csv.write_text('broken')
    elif damage=='columns':
        csv.write_text(csv.read_text().replace('flow_id','wrong',1)); fm['artifact']['sha256']=sha256_file(csv); write_json_atomically(flow,fm)
    elif damage=='row_count': fm['artifact']['row_count']+=1;write_json_atomically(flow,fm)
    elif damage=='version': fm['manifest_schema_version']='future';write_json_atomically(flow,fm)
    elif damage=='counts': cm['packet_counts']=[1];write_json_atomically(cohort,cm)
    elif damage=='policy': cm['context_source_policy']={};write_json_atomically(cohort,cm)
    elif damage=='source': fm['source']['sha256']='a'*64;write_json_atomically(flow,fm)
    elif damage=='cohort-id': cm['cohort_identity']='b'*64;write_json_atomically(cohort,cm)
    else:
        p=o.dataset_root/'dataset_manifest.json';m=load_json_object(p);m['target_chunk']=IDS[1];write_json_atomically(p,m)
    before={p:p.read_bytes() for p in o.dataset_root.rglob('*') if p.is_file()}
    with pytest.raises(ValueError): ex.run_extract(o,source_url_resolver=resolver)
    assert all(p.read_bytes()==b for p,b in before.items())


def test_target_acquisition_failure_is_durable_incomplete(setup,monkeypatch):
    o,calls=setup
    def fail(*a,**kw): raise OSError('/private/secret')
    monkeypatch.setattr(ex,'download_chunk',fail)
    with pytest.raises(ex.IncompleteExtractionError):
        ex.run_extract(o,source_url_resolver=resolver)
    path=o.dataset_root/'dataset_manifest.json'
    manifest=load_json_object(path)
    assert manifest['status']=='incomplete'
    assert manifest['chunks'][TARGET]['status']=='failed'
    assert all(manifest['chunks'][c]['status']=='pending' for c in IDS[1:])
    assert '/private/' not in path.read_text()


def test_failure_before_target_scan_reuses_provenance_and_checks_raw_source(setup,monkeypatch):
    o,calls=setup
    monkeypatch.setattr(ex,'ProcessPoolExecutor',ThreadPoolExecutor)
    scan=ex._scan_chunk_worker
    def fail_target(task):
        if task.chunk_id==TARGET: raise ValueError('failed target scan')
        return scan(task)
    monkeypatch.setattr(ex,'_scan_chunk_worker',fail_target)
    with pytest.raises(ex.IncompleteExtractionError):
        ex.run_extract(o,source_url_resolver=resolver)
    path=o.dataset_root/'dataset_manifest.json'
    assert load_json_object(path)['status']=='incomplete'
    raw=o.spool_root/f'{TARGET}.pcap.gz'; metadata=o.spool_root/f'{TARGET}.download.json'
    raw.write_bytes(raw.read_bytes()+b'changed')
    value=load_json_object(metadata);value['sha256']=sha256_file(raw);value['size_bytes']=raw.stat().st_size;write_json_atomically(metadata,value)
    with pytest.raises(ex.IncompleteExtractionError): ex.run_extract(o,source_url_resolver=resolver)
    assert load_json_object(path)['chunks'][TARGET]['status']=='failed'
    assert raw.exists() and metadata.exists()


def test_initializer_once_and_worker_ownership(setup,monkeypatch):
    o,calls=setup; monkeypatch.setattr(ex,'ProcessPoolExecutor',ThreadPoolExecutor)
    ex.run_extract(o,source_url_resolver=resolver)
    cm=load_json_object(o.dataset_root/'cohort/cohort_manifest.json')
    reads=[]; read=ex._read_csv
    monkeypatch.setattr(ex,'_read_csv',lambda *a:(reads.append(a[0]),read(*a))[1])
    ex._initialize_scan_worker(str(o.dataset_root/'cohort/target_cohort.csv'))
    before={p:p.read_bytes() for p in o.dataset_root.rglob('*') if p.is_file()}
    for c in IDS[:2]:
        source=ex.RawSourceIdentity(**dl.download_chunk(c,resolver(DAY,c),o.spool_root))
        stage=o.dataset_root/f'.worker-{c}';stage.mkdir()
        task=ex.ScanChunkTask(c,dl._paths(c,o.spool_root)[0],stage,o.dataset_root,source,cm['cohort_identity'])
        result=ex._scan_chunk_worker(task)
        assert result.staging==stage and task.capture_path.exists()
        assert set(p.name for p in stage.iterdir())=={'manifest.json','target_packets.parquet','source_context_packets.parquet'}
    assert len(reads)==1
    assert all(p.read_bytes()==b for p,b in before.items())


def test_invalid_final_is_reported_and_never_overwritten(setup,monkeypatch):
    o,calls=setup;monkeypatch.setattr(ex,'ProcessPoolExecutor',ThreadPoolExecutor)
    ex.run_extract(o,source_url_resolver=resolver)
    p=o.dataset_root/'observations'/IDS[2]/'target_packets.parquet';p.write_bytes(b'broken')
    before=p.read_bytes();calls.clear()
    with pytest.raises(ex.IncompleteExtractionError):
        ex.run_extract(o,source_url_resolver=resolver)
    path=o.dataset_root/'dataset_manifest.json'
    m=load_json_object(path)
    assert m['status']=='incomplete' and m['chunks'][IDS[2]]['status']=='failed'
    assert calls==[] and p.read_bytes()==before


def test_target_invalid_cache_does_not_block_independent_missing_chunk(setup,monkeypatch):
    import shutil
    o,calls=setup;monkeypatch.setattr(ex,'ProcessPoolExecutor',ThreadPoolExecutor)
    ex.run_extract(o,source_url_resolver=resolver)
    bad=o.dataset_root/'observations'/TARGET/'target_packets.parquet';bad.write_bytes(b'bad')
    shutil.rmtree(o.dataset_root/'observations'/IDS[-1]);calls.clear()
    with pytest.raises(ex.IncompleteExtractionError): ex.run_extract(o,source_url_resolver=resolver)
    m=load_json_object(o.dataset_root/'dataset_manifest.json')
    assert m['chunks'][TARGET]['status']=='failed'
    assert m['chunks'][IDS[-1]]['status']=='success'
    assert calls==[IDS[-1]] and bad.read_bytes()==b'bad'


def test_cache_reuses_without_raw_after_interrupted_metadata_deletion(setup,monkeypatch):
    o,calls=setup;monkeypatch.setattr(ex,'ProcessPoolExecutor',ThreadPoolExecutor)
    ex.run_extract(o,source_url_resolver=resolver)
    for c in IDS:
        source=load_json_object(o.dataset_root/'observations'/c/'manifest.json')['source']
        write_json_atomically(o.spool_root/f'{c}.download.json',source)
    calls.clear()
    assert ex.run_extract(o,source_url_resolver=resolver)==o.dataset_root
    assert calls==[]


def test_failed_second_provenance_publication_rolls_back_owned_first(setup,monkeypatch):
    o,calls=setup;publish=ex.obs._publish_chunk
    def fail_cohort(stage,final):
        if final==o.dataset_root/'cohort':raise OSError('publication failed')
        publish(stage,final)
    monkeypatch.setattr(ex.obs,'_publish_chunk',fail_cohort)
    with pytest.raises(ex.IncompleteExtractionError):ex.run_extract(o,source_url_resolver=resolver)
    assert not (o.dataset_root/'provenance').exists()
    assert not (o.dataset_root/'cohort').exists()
    assert (o.spool_root/f'{TARGET}.pcap.gz').exists()
    monkeypatch.setattr(ex.obs,'_publish_chunk',publish)
    monkeypatch.setattr(ex,'ProcessPoolExecutor',ThreadPoolExecutor)
    assert ex.run_extract(o,source_url_resolver=resolver)==o.dataset_root


@pytest.mark.parametrize('damage',['digest','null-identity','bool-count','bool-row-count','observations-symlink'])
def test_malformed_identity_or_paths_fail_before_writing(setup,monkeypatch,damage):
    import shutil
    o,calls=setup;monkeypatch.setattr(ex,'ProcessPoolExecutor',ThreadPoolExecutor)
    ex.run_extract(o,source_url_resolver=resolver)
    manifest=o.dataset_root/'dataset_manifest.json';value=load_json_object(manifest)
    if damage=='digest': value['cohort_identity']='not-a-digest'
    elif damage=='null-identity': value['cohort_identity']=None
    elif damage=='bool-count': value['packet_counts']=[True,2,3]
    elif damage=='bool-row-count':
        p=o.dataset_root/'cohort/cohort_manifest.json';m=load_json_object(p)
        # Change a two-row table to one row and update identity/checksum, so
        # boolean count cannot be rejected merely by mismatch with 2.
        csv=o.dataset_root/'cohort/target_cohort.csv';frame=pd.read_csv(csv).iloc[:1];frame.to_csv(csv,index=False)
        m['artifact']['sha256']=sha256_file(csv);m['artifact']['row_count']=True
        m['cohort_identity']=ex.cohort_identity(frame);write_json_atomically(p,m)
    else:
        outside=o.dataset_root.parent/'outside';outside.mkdir()
        shutil.rmtree(o.dataset_root/'observations')
        (o.dataset_root/'observations').symlink_to(outside,target_is_directory=True)
    write_json_atomically(manifest,value)
    calls.clear();before={p:p.read_bytes() for p in o.dataset_root.rglob('*') if p.is_file()}
    with pytest.raises(ValueError):ex.run_extract(o,source_url_resolver=resolver)
    assert calls==[] and all(p.read_bytes()==b for p,b in before.items())
    if damage=='observations-symlink': assert list(outside.iterdir())==[]


def test_target_reacquisition_failure_continues_safe_siblings(setup,monkeypatch):
    import shutil
    o,calls=setup;monkeypatch.setattr(ex,'ProcessPoolExecutor',ThreadPoolExecutor)
    ex.run_extract(o,source_url_resolver=resolver)
    for c in (TARGET,IDS[-1]):shutil.rmtree(o.dataset_root/'observations'/c)
    download=ex.download_chunk
    def fail_target(c,*a,**kw):
        if c==TARGET:raise OSError('target unavailable')
        return download(c,*a,**kw)
    monkeypatch.setattr(ex,'download_chunk',fail_target)
    with pytest.raises(ex.IncompleteExtractionError):ex.run_extract(o,source_url_resolver=resolver)
    m=load_json_object(o.dataset_root/'dataset_manifest.json')
    assert m['chunks'][TARGET]['status']=='failed' and m['chunks'][IDS[-1]]['status']=='success'


def test_preprovenance_resume_preserves_known_target_source(setup,monkeypatch):
    o,calls=setup;parse=ex.parse_target_flows
    def fail_parse(*a):raise ValueError('parse failed')
    monkeypatch.setattr(ex,'parse_target_flows',fail_parse)
    with pytest.raises(ex.IncompleteExtractionError):ex.run_extract(o,source_url_resolver=resolver)
    manifest=o.dataset_root/'dataset_manifest.json';before=load_json_object(manifest)['chunks'][TARGET]['source']
    raw=o.spool_root/f'{TARGET}.pcap.gz';meta=o.spool_root/f'{TARGET}.download.json'
    raw.write_bytes(raw.read_bytes()+b'changed');changed=load_json_object(meta)
    changed['size_bytes']=raw.stat().st_size;changed['sha256']=sha256_file(raw);write_json_atomically(meta,changed)
    monkeypatch.setattr(ex,'parse_target_flows',parse)
    with pytest.raises(ex.IncompleteExtractionError):ex.run_extract(o,source_url_resolver=resolver)
    assert not (o.dataset_root/'provenance').exists()
    assert load_json_object(manifest)['chunks'][TARGET]['source']==before


def test_complete_copy_reuses_without_original_roots_or_raw(setup,monkeypatch):
    import shutil
    o,calls=setup;monkeypatch.setattr(ex,'ProcessPoolExecutor',ThreadPoolExecutor)
    ex.run_extract(o,source_url_resolver=resolver)
    copied=o.dataset_root.parent/'copied';shutil.copytree(o.dataset_root,copied);shutil.rmtree(o.dataset_root);shutil.rmtree(o.spool_root)
    options=ex.ExtractOptions(DAY,TARGET,(1,2,3),2,copied,copied.parent/'new-spool');calls.clear()
    assert ex.run_extract(options,source_url_resolver=resolver)==copied
    assert calls==[] and not options.spool_root.exists()


@pytest.mark.parametrize('damage',['duplicate-id','protocol','ip','port','ip-version','bool-cohort-count'])
def test_all_flow_semantic_identifiers_are_validated(setup,monkeypatch,damage):
    o,calls=setup;monkeypatch.setattr(ex,'ProcessPoolExecutor',ThreadPoolExecutor)
    frames=[packet()]+[packet(src='192.0.2.44',sport=5000)]*4
    body=pcap_bytes([(i,frame,len(frame)) for i,frame in enumerate(frames)])
    class Response(BytesIO):headers={}
    monkeypatch.setattr(dl,'urlopen',lambda *a,**kw:Response(body))
    ex.run_extract(o,source_url_resolver=resolver)
    csv=o.dataset_root/'provenance/flows.csv';frame=pd.read_csv(csv);fm=o.dataset_root/'provenance/flow_manifest.json';m=load_json_object(fm)
    if damage=='bool-cohort-count':
        p=o.dataset_root/'cohort/cohort_manifest.json';cm=load_json_object(p);cm['packet_counts']=[True,2,3];write_json_atomically(p,cm)
    else:
        column,value={'duplicate-id':('flow_id',1),'protocol':('protocol',99),'ip':('src_ip','invalid'),'port':('src_port',65536),'ip-version':('ip_version',6)}[damage]
        frame.loc[1,column]=value;frame.to_csv(csv,index=False);m['artifact']['sha256']=sha256_file(csv);write_json_atomically(fm,m)
    before={p:p.read_bytes() for p in o.dataset_root.rglob('*') if p.is_file()}
    with pytest.raises(ValueError):ex.run_extract(o,source_url_resolver=resolver)
    assert all(p.read_bytes()==b for p,b in before.items())


def test_worker_rejects_indexes_from_changed_cohort(setup,monkeypatch):
    o,calls=setup;monkeypatch.setattr(ex,'ProcessPoolExecutor',ThreadPoolExecutor)
    ex.run_extract(o,source_url_resolver=resolver)
    path=o.dataset_root/'cohort/target_cohort.csv';cm=load_json_object(path.parent/'cohort_manifest.json')
    frame=pd.read_csv(path);frame.loc[0,'context_source_ip']='192.0.2.99';frame.to_csv(path,index=False)
    ex._initialize_scan_worker(str(path))
    source=ex.RawSourceIdentity(**dl.download_chunk(TARGET,resolver(DAY,TARGET),o.spool_root))
    stage=o.dataset_root/'.worker-changed-cohort';stage.mkdir()
    task=ex.ScanChunkTask(TARGET,dl._paths(TARGET,o.spool_root)[0],stage,o.dataset_root,source,cm['cohort_identity'])
    with pytest.raises(ValueError,match='cohort'):ex._scan_chunk_worker(task)
    assert list(stage.iterdir())==[] and task.capture_path.exists()


@pytest.mark.parametrize('bad_state',[None,[],{'status':'failed','error':None}])
def test_malformed_preprovenance_progress_is_explicit_failure(setup,monkeypatch,bad_state):
    o,calls=setup
    def fail(*a):raise OSError('target unavailable')
    monkeypatch.setattr(ex,'download_chunk',fail)
    with pytest.raises(ex.IncompleteExtractionError):ex.run_extract(o,source_url_resolver=resolver)
    p=o.dataset_root/'dataset_manifest.json';m=load_json_object(p);m['chunks'][TARGET]=bad_state;write_json_atomically(p,m)
    before=p.read_bytes()
    with pytest.raises(ValueError):ex.run_extract(o,source_url_resolver=resolver)
    assert p.read_bytes()==before


def test_cohort_observation_times_match_flows_exactly(setup,monkeypatch):
    o,calls=setup;monkeypatch.setattr(ex,'ProcessPoolExecutor',ThreadPoolExecutor)
    ex.run_extract(o,source_url_resolver=resolver)
    p=o.dataset_root/'cohort/target_cohort.csv';frame=pd.read_csv(p)
    frame.loc[0,'target_start_time']+=1e-8;frame.to_csv(p,index=False)
    manifest=p.parent/'cohort_manifest.json';m=load_json_object(manifest)
    m['artifact']['sha256']=sha256_file(p);write_json_atomically(manifest,m)
    with pytest.raises(ValueError):ex.run_extract(o,source_url_resolver=resolver)


def test_capacity_exhaustion_is_incomplete_and_resume_drains_raw(setup, monkeypatch):
    from mawi_context.chunks import expected_chunk_ids
    o, downloads = setup
    ids = expected_chunk_ids(DAY)[:10]
    monkeypatch.setattr(ex, 'expected_chunk_ids', lambda day: ids)
    monkeypatch.setattr(ex, 'ProcessPoolExecutor', ThreadPoolExecutor)
    scan = ex._scan_chunk_worker
    scanned = []
    def fail(task):
        scanned.append(task.chunk_id)
        raise ValueError('retained raw failure')
    monkeypatch.setattr(ex, '_scan_chunk_worker', fail)
    with pytest.raises(ex.IncompleteExtractionError):
        ex.run_extract(o, source_url_resolver=resolver)
    path = o.dataset_root/'dataset_manifest.json'
    first = load_json_object(path)
    retained = set(downloads)
    assert len(retained) == o.workers + 2
    assert len(scanned) == len(set(scanned)) == len(retained)
    assert len(list(o.spool_root.glob('*.pcap.gz'))) == len(retained)
    assert first['status'] == 'incomplete'
    assert all(first['chunks'][c]['status'] == ('failed' if c in retained else 'pending') for c in ids)
    assert not list((o.dataset_root/'observations').glob('20*'))

    downloads.clear()
    scanned.clear()
    def recover(task):
        scanned.append(task.chunk_id)
        return scan(task)
    monkeypatch.setattr(ex, '_scan_chunk_worker', recover)
    assert ex.run_extract(o, source_url_resolver=resolver) == o.dataset_root
    assert set(downloads) == set(ids) - retained
    assert set(scanned) == set(ids)
    assert load_json_object(path)['status'] == 'success'
    assert list(o.spool_root.iterdir()) == []


def test_target_bootstrap_respects_preexisting_full_spool(setup, monkeypatch):
    from mawi_context.chunks import expected_chunk_ids
    o, downloads = setup
    ids = expected_chunk_ids(DAY)[:10]
    monkeypatch.setattr(ex, 'expected_chunk_ids', lambda day: ids)
    for chunk in ids[1:o.workers+3]:
        dl.download_chunk(chunk, resolver(DAY, chunk), o.spool_root)
    before = {p: p.read_bytes() for p in o.spool_root.iterdir()}
    downloads.clear()
    with pytest.raises(ex.IncompleteExtractionError):
        ex.run_extract(o, source_url_resolver=resolver)
    assert downloads == []
    assert {p: p.read_bytes() for p in o.spool_root.iterdir()} == before
    m = load_json_object(o.dataset_root/'dataset_manifest.json')
    assert m['status'] == 'incomplete'
    assert all(m['chunks'][c]['status'] == 'pending' for c in ids[1:])
