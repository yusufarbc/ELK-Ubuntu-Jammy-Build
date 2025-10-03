#!/usr/bin/env bash
# lab_start.sh - lab ortamını başlatmak için yardımcı script
# Yapacaklar:
#  - self-signed sertifikaları oluştur (tools/generate-self-signed-certs.sh)
#  - ELASTIC_PASSWORD ortam değişkenini kontrol et / iste
#  - docker compose up -d çalıştır
#  - Elasticsearch sağlığını bekle (kısa loop)

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker bulunamadı. Lütfen Docker kurun." >&2
  exit 1
fi
if ! command -v docker-compose >/dev/null 2>&1 && ! docker compose version >/dev/null 2>&1; then
  echo "docker compose bulunamadı. Lütfen Docker Compose veya Docker CLI Compose eklentisini kurun." >&2
  exit 1
fi

# Sertifikalar
if [ ! -d "$ROOT_DIR/certs" ] || [ -z "$(ls -A "$ROOT_DIR/certs" 2>/dev/null || true)" ]; then
  echo "./certs dizini boş veya yok. Self-signed sertifikalar oluşturuluyor..."
  chmod +x "$ROOT_DIR/tools/generate-self-signed-certs.sh"
  sudo "$ROOT_DIR/tools/generate-self-signed-certs.sh"
else
  echo "certs dizini dolu, atlanıyor. (./certs)"
fi

# ELASTIC_PASSWORD
if [ -z "${ELASTIC_PASSWORD-}" ]; then
  read -rsp "Elasticsearch 'elastic' kullanıcısı için güçlü bir parola girin: " ELASTIC_PASSWORD
  echo
  export ELASTIC_PASSWORD
fi

# Start compose (use docker compose if available)
if command -v docker-compose >/dev/null 2>&1; then
  docker-compose up -d
else
  docker compose up -d
fi

# Wait for Elasticsearch to be available
echo "Elasticsearch başlatılıyor, bekleniyor (maks 180s)..."
for i in $(seq 1 36); do
  if curl -s -k -u elastic:"$ELASTIC_PASSWORD" https://localhost:9200/ >/dev/null 2>&1; then
    echo "Elasticsearch erişilebilir oldu."
    exit 0
  fi
  sleep 5
done

echo "Elasticsearch başlatılamadı veya erişilemiyor. Container loglarını kontrol edin: docker compose logs elasticsearch" >&2
exit 2
