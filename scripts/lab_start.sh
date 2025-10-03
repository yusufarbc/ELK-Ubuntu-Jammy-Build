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

echo "This helper previously used Docker Compose for a test lab. The repository is now focused on a Docker-less single-host installer."
echo "Use the main installer or the Python test harness instead."

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

echo "If you want to run the apt-based installer on this host, run:"
echo "  sudo bash $ROOT_DIR/elk_setup_ubuntu_jammy.sh --non-interactive --password 'SOME_STRONG_PW'"
echo
echo "Or, to locally test Logstash filters with the Python harness (no Docker), see tools/logstash_test README and run the harness script."
exit 0
