#!/usr/bin/env bash
# Basit test: examples/kaspersky/sample_kaspersky.json içeriğini Logstash syslog portuna gönder
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_HOST="localhost"
TARGET_PORT=5514

if [ ! -f "$ROOT_DIR/examples/kaspersky/sample_kaspersky.json" ]; then
  echo "Örnek dosya bulunamadı: examples/kaspersky/sample_kaspersky.json" >&2
  exit 1
fi

# Netcat ile TCP gönder (sütun sonu ekleyerek)
cat "$ROOT_DIR/examples/kaspersky/sample_kaspersky.json" | nc -w 1 $TARGET_HOST $TARGET_PORT

echo "Örnek Kaspersky JSON'u $TARGET_HOST:$TARGET_PORT adresine gönderildi. Logstash pipeline'ınızı kontrol edin."
