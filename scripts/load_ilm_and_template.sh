#!/usr/bin/env bash
# load_ilm_and_template.sh - ILM policy ve index template yükler
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -z "${ELASTIC_PASSWORD-}" ]; then
  echo "Lütfen ELASTIC_PASSWORD ortam değişkenini ayarlayın veya script çalıştırırken export edin." >&2
  echo "Örnek: export ELASTIC_PASSWORD='SOME_STRONG_PW'" >&2
  exit 1
fi

echo "ILM policy yükleniyor..."
curl -s -k -u elastic:"$ELASTIC_PASSWORD" -X PUT "https://localhost:9200/_ilm/policy/logs-30d-delete" \
  -H 'Content-Type: application/json' -d @examples/ilm/logs-30d-delete.json | jq '.'

echo "Index template yükleniyor..."
curl -s -k -u elastic:"$ELASTIC_PASSWORD" -X PUT "https://localhost:9200/_index_template/logs-template" \
  -H 'Content-Type: application/json' -d @examples/index_template/logs-template.json | jq '.'

echo "Tamam."
