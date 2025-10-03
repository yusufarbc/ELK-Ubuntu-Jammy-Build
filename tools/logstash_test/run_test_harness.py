#!/usr/bin/env python3
"""
Lightweight Logstash filter test harness (Docker-less).
Mimics a subset of filters from tools/logstash_test/pipeline/00-test.conf:
 - JSON detection/parsing
 - Simple ASA regex extraction
 - FortiGate key=value extraction
Outputs JSON lines to tools/logstash_test/output/output.json and prints a small summary.
"""
import re
import json
from pathlib import Path
from datetime import datetime
import calendar

ROOT = Path(__file__).resolve().parent
SAMPLES = ROOT / 'samples'
OUT = ROOT / 'output' / 'output.json'
OUT.parent.mkdir(parents=True, exist_ok=True)

asa_re = re.compile(r"%ASA-[0-9]+-[0-9]+: Built (?P<direction>\w+) (?P<transport>\w+) connection (?P<conn_id>\d+) for (?:[^:]+:)?(?P<src_ip>\d+\.\d+\.\d+\.\d+)/(?P<src_port>\d+) to (?:[^:]+:)?(?P<dst_ip>\d+\.\d+\.\d+\.\d+)/(?P<dst_port>\d+)")

# syslog header like: 'Oct  3 12:34:56 hostname rest'
syslog_header_re = re.compile(r'^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$')

# FortiGate kv: simple key=value with whitespace separators; values may be quoted
# Use double-quoted raw string so single quotes inside pattern don't need escaping
kv_re = re.compile(r"(\w+)=((?:\"[^\"]*\")|(?:'[^']*')|[^\s]+)")

results = []

for path in SAMPLES.glob('*'):
    text = path.read_text(encoding='utf-8')
    # If file looks like a JSON document (multi-line), parse whole content as JSON
    if path.suffix.lower() == '.json' or text.lstrip().startswith('{'):
        event = {'message': text, '@source_file': str(path.name)}
        try:
            parsed = json.loads(text)
            event['parsed_json'] = parsed
            # minimal renames similar to pipeline
            if 'ComputerName' in parsed:
                event.setdefault('host', {})['name'] = parsed['ComputerName']
            if 'ThreatName' in parsed:
                event.setdefault('threat', {})['name'] = parsed['ThreatName']
            if 'ThreatSeverity' in parsed:
                event.setdefault('threat', {})['severity'] = parsed['ThreatSeverity']
            event['event.module'] = 'kaspersky'
            event['event.dataset'] = 'kaspersky.av'
            # timestamp normalization if present
            if 'Timestamp' in parsed:
                try:
                    # expect ISO8601
                    dt = datetime.fromisoformat(parsed['Timestamp'].replace('Z', '+00:00'))
                    event['@timestamp'] = dt.isoformat()
                except Exception:
                    pass
        except Exception as e:
            event['json_error'] = str(e)
        results.append(event)
        continue

    # otherwise process line-by-line for plain-text samples
    for line in text.strip().splitlines():
        line = line.rstrip('\n')
        event = {'message': line, '@source_file': str(path.name)}

        # ASA detection (handle syslog header)
        sm = syslog_header_re.search(line)
        rest_line = line
        if sm:
            hdr = sm.groupdict()
            rest_line = hdr['rest']
            event.setdefault('host', {})['name'] = hdr['host']
            # Try to build @timestamp using current year
            try:
                year = datetime.utcnow().year
                dt = datetime.strptime(f"{hdr['ts']} {year}", "%b %d %H:%M:%S %Y")
                # convert to ISO
                event['@timestamp'] = dt.isoformat()
            except Exception:
                pass

        m = asa_re.search(rest_line)
        if m:
            event['event.module'] = 'cisco_asa'
            event['event.dataset'] = 'cisco.asa'
            event['asa'] = m.groupdict()
            # convert port types
            try:
                event['asa']['src_port'] = int(event['asa']['src_port'])
                event['asa']['dst_port'] = int(event['asa']['dst_port'])
            except Exception:
                pass
            results.append(event)
            continue

        # FortiGate kv parsing
        if 'srcip=' in line or 'dstip=' in line or 'action=' in line:
            kvs = { }
            for km in kv_re.finditer(line):
                k = km.group(1)
                v = km.group(2)
                if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                    v = v[1:-1]
                kvs[k] = v
            # normalize
            if 'srcip' in kvs:
                event.setdefault('source', {})['ip'] = kvs.get('srcip')
            if 'srcport' in kvs:
                try:
                    event.setdefault('source', {})['port'] = int(kvs.get('srcport'))
                except Exception:
                    event.setdefault('source', {})['port'] = kvs.get('srcport')
            if 'dstip' in kvs:
                event.setdefault('destination', {})['ip'] = kvs.get('dstip')
            if 'dstport' in kvs:
                try:
                    event.setdefault('destination', {})['port'] = int(kvs.get('dstport'))
                except Exception:
                    event.setdefault('destination', {})['port'] = kvs.get('dstport')
            event['event.module'] = 'fortigate'
            event['event.dataset'] = 'fortigate.firewall'
            # normalize numeric fields and promote to ECS-like names
            # srcport/dstport/proto/duration
            if 'srcport' in kvs:
                try:
                    event.setdefault('source', {})['port'] = int(kvs.get('srcport'))
                except Exception:
                    event.setdefault('source', {})['port'] = kvs.get('srcport')
            if 'dstport' in kvs:
                try:
                    event.setdefault('destination', {})['port'] = int(kvs.get('dstport'))
                except Exception:
                    event.setdefault('destination', {})['port'] = kvs.get('dstport')
            if 'proto' in kvs:
                # map numeric proto to transport name when possible
                proto = kvs.get('proto')
                if proto in ('6', '06'):
                    event.setdefault('network', {})['transport'] = 'tcp'
                elif proto in ('17',):
                    event.setdefault('network', {})['transport'] = 'udp'
                else:
                    event.setdefault('network', {})['transport'] = proto
            if 'duration' in kvs:
                try:
                    event['duration'] = int(kvs.get('duration'))
                except Exception:
                    event['duration'] = kvs.get('duration')
            # Build @timestamp if date+time fields exist
            if 'date' in kvs and 'time' in kvs:
                try:
                    dt = datetime.fromisoformat(f"{kvs.get('date')}T{kvs.get('time')}")
                    event['@timestamp'] = dt.isoformat()
                except Exception:
                    pass
            # keep original kvs for debugging
            event.update(kvs)
            results.append(event)
            continue

        # fallback: record message
        results.append(event)

# write output
with OUT.open('w', encoding='utf-8') as f:
    for ev in results:
        f.write(json.dumps(ev, ensure_ascii=False) + "\n")

# print summary
counts = {}
for ev in results:
    ds = ev.get('event.dataset', 'raw')
    counts[ds] = counts.get(ds, 0) + 1

print("Parsed events:")
for ds, c in counts.items():
    print(f" - {ds}: {c}")
print(f"Output written to {OUT}")
