"""Full 96-chunk portable contract, using synthetic captures only."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
from io import BytesIO
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import urllib.request

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from mawi_context import aggregation as ag
from mawi_context import downloader as dl, extraction as ex
from mawi_context.chunks import expected_chunk_ids
from mawi_context.hashing import sha256_file
from mawi_context.manifests import load_json_object, write_json_atomically
from mawi_context.observations import load_validated_chunk

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'helpers'))
from pcap_factory import packet, pcap_bytes

DAY = '2026-04-08'
IDS = expected_chunk_ids(DAY)
TARGET = IDS[56]


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()}


def read_results(output):
    result = {}
    for n in (1,2,3):
        with (output/f'packet_count_{n}'/'context.csv').open(newline='') as stream:
            reader = csv.DictReader(stream)
            assert tuple(reader.fieldnames) == ag.CONTEXT_RESULT_COLUMNS
            rows = list(reader)
            assert [int(r['target_flow_id']) for r in rows] == sorted(int(r['target_flow_id']) for r in rows)
            result[n] = rows
    return result


@pytest.fixture(scope='module')
def complete_dataset(tmp_path_factory):
    base = tmp_path_factory.mktemp('complete-96')
    options = ex.ExtractOptions(DAY,TARGET,(1,2,3),2,base/'dataset',base/'spool')
    tcp1 = packet()
    udp2 = packet(protocol=17,sport=2222)
    tcp3 = packet(sport=3333)
    other1 = packet(sport=4444)
    target = [(1000.125,tcp1),(1001.125,udp2),(1002.125,udp2),
              (1003.125,tcp3),(1004.125,tcp3),(1005.125,tcp3),(2000.125,other1)]
    previous = [(999.125,tcp1)]
    reverse = packet(src='192.0.2.2',dst='192.0.2.10',sport=80,dport=1234,flags=18)
    following = [(1001.125,reverse)]
    bodies = {TARGET: pcap_bytes((t,f,len(f)) for t,f in target),
              IDS[55]: pcap_bytes((t,f,len(f)) for t,f in previous),
              IDS[57]: pcap_bytes((t,f,len(f)) for t,f in following)}
    class Response(BytesIO):
        headers = {}
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(dl, 'urlopen', lambda url,timeout: Response(bodies.get(url.rsplit('/',1)[-1],pcap_bytes())))
        patch.setattr(ex, 'ProcessPoolExecutor', ThreadPoolExecutor)
        ex.run_extract(options,source_url_resolver=lambda day,chunk:'https://fixture.test/'+chunk)
    assert load_json_object(options.dataset_root/'dataset_manifest.json')['status'] == 'success'
    assert len(list((options.dataset_root/'observations').iterdir())) == 96
    for chunk in IDS:
        load_validated_chunk(options.dataset_root,chunk,
            expected_cohort_identity=load_json_object(options.dataset_root/'dataset_manifest.json')['cohort_identity'])
    shutil.rmtree(options.spool_root)
    return options.dataset_root


@pytest.fixture
def dataset(complete_dataset,tmp_path):
    return Path(shutil.copytree(complete_dataset,tmp_path/'portable'))


def forbid(*args,**kwargs):
    raise AssertionError('network/acquisition/raw access forbidden')


def test_portable_copy_without_original_raw_spool_or_network(dataset,tmp_path,monkeypatch):
    baseline = ag.run_aggregate(ag.AggregateOptions(dataset,tmp_path/'baseline'))
    copied = Path(shutil.copytree(dataset,tmp_path/'copied'))
    shutil.rmtree(dataset)
    monkeypatch.setattr(urllib.request,'urlopen',forbid)
    monkeypatch.setattr(socket,'create_connection',forbid)
    monkeypatch.setattr(dl,'urlopen',forbid)
    monkeypatch.setattr(ex,'download_chunk',forbid)
    monkeypatch.setattr(ex,'run_extract',forbid)
    monkeypatch.setattr(ex,'_target_provenance',forbid)
    monkeypatch.setattr(ex,'parse_target_flows',forbid)
    before = snapshot(copied)
    output = ag.run_aggregate(ag.AggregateOptions(copied,tmp_path/'results'))
    assert snapshot(copied) == before
    assert snapshot(output) == snapshot(baseline)
    rows = read_results(output)
    assert [len(rows[n]) for n in (1,2,3)] == [2,1,1]
    one = rows[1][0]
    assert int(one['same_tuple_packet_count_24h']) == 3
    assert int(one['same_tuple_before_count']) == int(one['same_tuple_after_count']) == 1
    assert float(one['previous_same_tuple_gap_seconds']) == float(one['next_same_tuple_gap_seconds']) == 1
    assert int(one['tcp_control_packet_count_24h']) == 7
    assert int(one['tcp_outbound_plain_syn_count_24h']) == 6
    assert int(one['tcp_inbound_syn_ack_count_24h']) == 1
    assert int(rows[2][0]['udp_outbound_packet_count_24h']) == 2
    assert not list(output.glob('*.sqlite*'))
    assert not any(c in ag.CONTEXT_RESULT_COLUMNS for c in ('scan','scan_like','anomaly','malicious','benign'))


def test_all_chunks_validated_before_ingest_and_bounded_batches(dataset,tmp_path,monkeypatch):
    output = tmp_path/'results'
    reference = ag.run_aggregate(ag.AggregateOptions(dataset,output))
    before = snapshot(reference)
    validated = []
    load = ag.load_validated_chunk
    ingest = ag._ingest_observations
    batches = []
    original = pq.ParquetFile.iter_batches
    def iter_batches(self,*args,**kwargs):
        for batch in original(self,*args,**kwargs):
            if kwargs.get('batch_size') == 2:
                batches.append(batch.num_rows)
            yield batch
    def reload(root,chunk,**kwargs):
        result = load(root,chunk,**kwargs)
        validated.append(chunk)
        return result
    def ingest_checked(*args,**kwargs):
        assert tuple(validated) == IDS
        return ingest(*args,**kwargs)
    monkeypatch.setattr(ag,'load_validated_chunk',reload)
    monkeypatch.setattr(ag,'_ingest_observations',ingest_checked)
    monkeypatch.setattr(ag,'_BATCH_SIZE',2)
    monkeypatch.setattr(pq.ParquetFile,'iter_batches',iter_batches)
    ag.run_aggregate(ag.AggregateOptions(dataset,output))
    assert snapshot(output) == before
    assert len(batches) > 4 and max(batches) <= 2


@pytest.mark.parametrize('damage', [
    'incomplete','missing-state','failed-state','unexpected-list','unexpected-state','malformed','root-list',
    'dataset-version','bad-day','bad-target','counts-empty','counts-duplicate','counts-bool','counts-zero',
    'identity','identity-uppercase','cohort-csv','flow-csv','checksum','chunk-schema','missing-file','extra-file',
    'observation-version','flow-path','cohort-path','chunk-path','source-mismatch','flow-version',
    'flow-columns','flow-row-count','flow-policy','cohort-policy','tool','cohort-counts','cohort-time',
    'cohort-manifest-id','source-shape','missing-provenance','extra-provenance',
])
def test_reject_invalid_portable_dataset_before_sqlite_or_ingest(dataset,tmp_path,monkeypatch,damage):
    path=dataset/'dataset_manifest.json'
    dm=load_json_object(path)
    fm_path=dataset/'provenance/flow_manifest.json'; fm=load_json_object(fm_path)
    cm_path=dataset/'cohort/cohort_manifest.json'; cm=load_json_object(cm_path)
    chunk=dataset/'observations'/IDS[-1]; packet_path=chunk/'target_packets.parquet'
    if damage=='incomplete': dm['status']='incomplete'
    elif damage=='missing-state': dm['chunks'].pop(IDS[-1])
    elif damage=='failed-state': dm['chunks'][IDS[-1]]['status']='failed'
    elif damage=='unexpected-list': dm['expected_chunk_ids']=list(IDS[:4])
    elif damage=='unexpected-state': dm['chunks']['extra']=dm['chunks'][IDS[-1]]
    elif damage=='dataset-version': dm['manifest_schema_version']='future'
    elif damage=='bad-day': dm['day']='2026-02-30'
    elif damage=='bad-target': dm['target_chunk']='202604091400'
    elif damage.startswith('counts-'): dm['packet_counts']={'counts-empty':[], 'counts-duplicate':[1,1], 'counts-bool':[True,2,3], 'counts-zero':[0,2,3]}[damage]
    elif damage.startswith('identity'): dm['cohort_identity']='b'*64 if damage=='identity' else 'A'*64
    elif damage in ('cohort-csv','flow-csv'):
        (dataset/('cohort/target_cohort.csv' if damage=='cohort-csv' else 'provenance/flows.csv')).write_text('broken')
    elif damage=='checksum': packet_path.write_bytes(packet_path.read_bytes()+b'changed')
    elif damage=='chunk-schema':
        pq.write_table(pa.table({'wrong': [1]}),packet_path)
        p=chunk/'manifest.json'; m=load_json_object(p); m['artifacts']['target_packets']['sha256']=sha256_file(packet_path); write_json_atomically(p,m)
    elif damage=='missing-file': packet_path.unlink()
    elif damage=='extra-file': (chunk/'extra').write_text('extra')
    elif damage=='observation-version': dm['observation_schemas']['target_packets']='future'
    elif damage=='flow-path': dm['flow_manifest']='/absolute/path'
    elif damage=='cohort-path': cm['artifact']['path']='../escape'
    elif damage=='chunk-path': dm['chunks'][IDS[-1]]['manifest']='observations/wrong/manifest.json'
    elif damage=='source-mismatch': dm['chunks'][IDS[-1]]['source']['sha256']='b'*64
    elif damage=='flow-version': fm['artifact']['schema_version']='future'
    elif damage=='flow-columns':
        p=dataset/'provenance/flows.csv'; p.write_text(p.read_text().replace('flow_id','wrong',1)); fm['artifact']['sha256']=sha256_file(p)
    elif damage=='flow-row-count': fm['artifact']['row_count']+=1
    elif damage=='flow-policy': fm['flow_definition']['inactivity_timeout']=60
    elif damage=='cohort-policy': cm['context_source_policy']={}
    elif damage=='tool': dm['tool']['version']='future'
    elif damage=='cohort-counts': cm['packet_counts']=[1]
    elif damage=='cohort-time':
        p=dataset/'cohort/target_cohort.csv'; frame=pd.read_csv(p); frame.loc[0,'target_start_time']+=1e-8; frame.to_csv(p,index=False); cm['artifact']['sha256']=sha256_file(p)
    elif damage=='cohort-manifest-id': cm['cohort_identity']='b'*64
    elif damage=='source-shape': fm['source']['local_path']='/raw'
    elif damage=='extra-provenance': (dataset/'provenance/extra').write_text('extra')
    write_json_atomically(path,dm); write_json_atomically(fm_path,fm); write_json_atomically(cm_path,cm)
    if damage=='malformed': path.write_text('{')
    elif damage=='root-list': path.write_text('[]')
    elif damage=='missing-provenance': fm_path.unlink()
    before=snapshot(dataset)
    monkeypatch.setattr(ag,'_ingest_observations',forbid)
    with pytest.raises((ValueError,OSError)):
        ag.run_aggregate(ag.AggregateOptions(dataset,tmp_path/'results'))
    assert snapshot(dataset)==before
    assert not (tmp_path/'results').exists()


@pytest.mark.parametrize('failure',['ingest','write-second-group','replace'])
def test_failure_retains_sqlite_and_no_partial_final_csv(dataset,tmp_path,monkeypatch,failure):
    before=snapshot(dataset); output=tmp_path/'results'
    def fail(*a,**kw): raise OSError('injected failure')
    if failure=='ingest':
        original=ag._ingest_observations
        def ingest(*args,**kwargs):
            original(*args,**kwargs)
            raise OSError('injected failure')
        monkeypatch.setattr(ag,'_ingest_observations',ingest)
    elif failure=='write-second-group':
        original=ag._write_result_group
        def write(db,count,path):
            if count==2: raise OSError('injected failure')
            return original(db,count,path)
        monkeypatch.setattr(ag,'_write_result_group',write)
    else: monkeypatch.setattr(ag.os,'replace',fail)
    with pytest.raises(OSError,match='injected'):
        ag.run_aggregate(ag.AggregateOptions(dataset,output))
    databases=list(output.glob('*.sqlite'))
    assert len(databases)==1
    with sqlite3.connect(databases[0]) as db:
        assert db.execute('SELECT count(*) FROM cohort').fetchone()[0]==4
    assert not list(output.rglob('context.csv'))
    assert snapshot(dataset)==before


@pytest.mark.parametrize('bad', ['id','protocol','tuple'])
def test_target_row_must_match_cohort_bidirectional_key(dataset,tmp_path,bad):
    path=dataset/'observations'/TARGET/'target_packets.parquet'
    table=pq.read_table(path); rows=table.to_pylist()
    field,value={'id':('target_flow_id',999),'protocol':('protocol',17),'tuple':('dst_port',999)}[bad]
    rows[0][field]=value
    pq.write_table(pa.Table.from_pylist(rows,schema=table.schema),path)
    mp=path.parent/'manifest.json'; m=load_json_object(mp);m['artifacts']['target_packets']['sha256']=sha256_file(path);write_json_atomically(mp,m)
    before=snapshot(dataset)
    with pytest.raises(ValueError,match='target observation'):
        ag.run_aggregate(ag.AggregateOptions(dataset,tmp_path/'results'))
    assert snapshot(dataset)==before
    assert len(list((tmp_path/'results').glob('*.sqlite')))==1
    assert not list((tmp_path/'results').rglob('context.csv'))


def test_default_output_and_cli_contract(dataset,tmp_path,monkeypatch,capsys):
    monkeypatch.chdir(tmp_path)
    assert ag.run_aggregate(ag.AggregateOptions(dataset)) == Path('results')/TARGET
    args=argparse.Namespace(dataset=str(dataset))
    assert ag.run_aggregate_cli(args)==0
    # Exercise the installed entry point, which owns late dispatch.
    result=subprocess.run([str(Path(sys.executable).parent/'mawi-context'),'aggregate','--dataset',str(dataset)],capture_output=True,text=True)
    assert result.returncode==0, result.stderr
    args.dataset=str(tmp_path/'missing')
    assert ag.run_aggregate_cli(args)!=0
    assert 'aggregate failed' in capsys.readouterr().err


@pytest.mark.parametrize('counts', [(9,), (4,9)])
def test_other_packet_counts_and_header_only_groups(tmp_path,monkeypatch,counts):
    # Keep all 96 IDs; include an empty group and an optional nonempty count 4.
    options=ex.ExtractOptions(DAY,TARGET,counts,2,tmp_path/'custom-dataset',tmp_path/'spool')
    frame=packet()
    body=pcap_bytes((1000+i,frame,len(frame)) for i in range(4))
    class Response(BytesIO): headers={}
    monkeypatch.setattr(dl,'urlopen',lambda url,timeout:Response(body if 4 in counts and url.endswith(TARGET) else pcap_bytes()))
    monkeypatch.setattr(ex,'ProcessPoolExecutor',ThreadPoolExecutor)
    ex.run_extract(options,source_url_resolver=lambda day,chunk:'https://fixture.test/'+chunk)
    output=ag.run_aggregate(ag.AggregateOptions(options.dataset_root,tmp_path/'results'))
    assert {p.name for p in output.iterdir()}=={f'packet_count_{n}' for n in counts}
    if 4 in counts:
        with (output/'packet_count_4/context.csv').open() as stream:
            row=list(csv.DictReader(stream))[0]
            assert int(row['observed_packet_count'])==int(row['same_tuple_packet_count_24h'])==4
    with (output/'packet_count_9/context.csv').open() as stream:
        assert list(csv.reader(stream))==[list(ag.CONTEXT_RESULT_COLUMNS)]


def test_output_inside_dataset_rejected(dataset):
    before=snapshot(dataset)
    with pytest.raises(ValueError): ag.run_aggregate(ag.AggregateOptions(dataset,dataset/'results'))
    assert snapshot(dataset)==before


@pytest.mark.parametrize('selected', [False,True])
def test_capture_order_timestamps_preserved_and_only_selected_reversed_interval_fails(tmp_path,monkeypatch,selected):
    counts=(1,2) if selected else (1,)
    options=ex.ExtractOptions(DAY,TARGET,counts,2,tmp_path/'dataset',tmp_path/'spool')
    frame=packet(sport=4444)
    body=pcap_bytes([(1000.125,frame,len(frame)),(999.125,frame,len(frame))])
    class Response(BytesIO): headers={}
    monkeypatch.setattr(dl,'urlopen',lambda url,timeout:Response(body if url.endswith(TARGET) else pcap_bytes()))
    monkeypatch.setattr(ex,'ProcessPoolExecutor',ThreadPoolExecutor)
    ex.run_extract(options,source_url_resolver=lambda day,chunk:'https://fixture.test/'+chunk)
    before=snapshot(options.dataset_root)
    output=tmp_path/'results'
    if selected:
        with pytest.raises(ValueError,match='target interval.*start.*end'):
            ag.run_aggregate(ag.AggregateOptions(options.dataset_root,output))
    else:
        ag.run_aggregate(ag.AggregateOptions(options.dataset_root,output))
        with (output/'packet_count_1/context.csv').open() as stream:
            assert list(csv.reader(stream))==[list(ag.CONTEXT_RESULT_COLUMNS)]
    assert snapshot(options.dataset_root)==before


@pytest.mark.parametrize('existing',[False,True])
def test_late_replace_failure_leaves_only_complete_csvs_and_retains_db(dataset,tmp_path,monkeypatch,existing):
    output=tmp_path/'results'
    baseline=ag.run_aggregate(ag.AggregateOptions(dataset,tmp_path/'baseline'))
    if existing:
        shutil.copytree(baseline,output)
    replace=ag.os.replace
    calls=0
    def fail_second(source,destination):
        nonlocal calls
        calls+=1
        if calls==2: raise OSError('late publication failure')
        return replace(source,destination)
    before=snapshot(dataset)
    monkeypatch.setattr(ag.os,'replace',fail_second)
    with pytest.raises(OSError,match='late publication'):
        ag.run_aggregate(ag.AggregateOptions(dataset,output))
    for path in output.rglob('context.csv'):
        assert path.read_bytes()==(baseline/path.relative_to(output)).read_bytes()
    assert len(list(output.rglob('context.csv')))==(3 if existing else 1)
    assert len(list(output.glob('*.sqlite')))==1
    assert snapshot(dataset)==before


@pytest.mark.parametrize('bad',['ack-only','unrelated-tcp','noncandidate-udp'])
def test_source_rows_must_obey_existing_retention_policy(dataset,tmp_path,bad):
    path=dataset/'observations'/TARGET/'source_context_packets.parquet'
    table=pq.read_table(path); rows=table.to_pylist()
    if bad=='ack-only': rows[0]['tcp_flags_raw']=16
    elif bad=='unrelated-tcp':
        rows[0]['src_ip']='198.51.100.1'; rows[0]['dst_ip']='198.51.100.2'
    else:
        next(row for row in rows if row['protocol']==17)['src_ip']='198.51.100.1'
    pq.write_table(pa.Table.from_pylist(rows,schema=table.schema),path)
    mp=path.parent/'manifest.json'; m=load_json_object(mp)
    m['artifacts']['source_context_packets']['sha256']=sha256_file(path);write_json_atomically(mp,m)
    before=snapshot(dataset)
    with pytest.raises(ValueError,match='source observation.*retention policy'):
        ag.run_aggregate(ag.AggregateOptions(dataset,tmp_path/'results'))
    assert snapshot(dataset)==before
    assert len(list((tmp_path/'results').glob('*.sqlite')))==1
    assert not list((tmp_path/'results').rglob('context.csv'))
