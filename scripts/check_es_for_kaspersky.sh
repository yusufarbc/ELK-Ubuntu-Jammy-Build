#!/usr/bin/env bash
# Basit kontrol: ES'de son indekslenen kaspersky eventini arar
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -z "${ELASTIC_PASSWORD-}" ]; then
  echo "Lütfen ELASTIC_PASSWORD ortam değişkenini ayarlayın." >&2
  exit 1
fi

# Kibana index patternimiz outputs.conf'da logs-%{[event][dataset]}-YYYY.MM.dd olarak ayarlandı
# Kaspersky pipeline event.dataset="kaspersky.av" ekleniyor, o yüzden indeks adı logs-kaspersky.av-YYYY.MM.dd olabilir.
# Sorgu: son 5 dakikada threat.name içeren kayıtlar
curl -s -k -u elastic:"$ELASTIC_PASSWORD" "https://localhost:9200/logs-kaspersky.av-*/_search?size=5" -H 'Content-Type: application/json' -d '{"query":{"exists":{"field":"threat.name"}},"sort":[{"@timestamp":{"order":"desc"}}]}' | jq '.'
