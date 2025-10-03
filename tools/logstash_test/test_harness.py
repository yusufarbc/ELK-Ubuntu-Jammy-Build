import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / 'output' / 'output.json'

def load_events():
    with OUT.open(encoding='utf-8') as f:
        for line in f:
            yield json.loads(line)


def test_kaspersky_parsed():
    events = list(load_events())
    kasp = [e for e in events if e.get('event.module') == 'kaspersky']
    assert len(kasp) == 1, "Expected one kaspersky event"
    e = kasp[0]
    assert e.get('host', {}).get('name') == 'host01.corp.local'
    assert e.get('threat', {}).get('name') == 'Malicious.File.Example'


def test_asa_ports_int():
    events = list(load_events())
    asas = [e for e in events if e.get('event.dataset') == 'cisco.asa']
    assert len(asas) >= 1
    for a in asas:
        asa = a.get('asa', {})
        assert isinstance(asa.get('src_port'), int)
        assert isinstance(asa.get('dst_port'), int)


def test_fortigate_ports_int():
    events = list(load_events())
    fgs = [e for e in events if e.get('event.module') == 'fortigate']
    assert len(fgs) == 1
    fg = fgs[0]
    assert isinstance(fg.get('source', {}).get('port'), int)
    assert isinstance(fg.get('destination', {}).get('port'), int)
