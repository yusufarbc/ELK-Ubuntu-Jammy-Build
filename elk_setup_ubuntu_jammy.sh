#!/usr/bin/env bash
set -euo pipefail

log(){ echo -e "[*] $*"; }
die(){ echo -e "[-] $*" >&2; exit 1; }

[[ $(id -u) -eq 0 ]] || die "Lütfen sudo/root ile çalıştırın."
export DEBIAN_FRONTEND=noninteractive

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

# ---------- 1) Bağımlılıklar ----------
log "Paket listesi güncelleniyor..."
apt-get update -y
log "Gerekli bağımlılıklar kuruluyor..."
apt-get install -y curl wget jq unzip apt-transport-https gnupg2

# ---------- 2) Elastic APT deposu (tek satır, idempotent) ----------
KEY_FILE="/usr/share/keyrings/elasticsearch-keyring.gpg"
REPO_FILE="/etc/apt/sources.list.d/elastic-9.x.list"

log "Elastic GPG anahtarı ekleniyor (idempotent)..."
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor > "${KEY_FILE}.tmp"
install -m 0644 "${KEY_FILE}.tmp" "${KEY_FILE}"
rm -f "${KEY_FILE}.tmp"

log "Elastic deposu yazılıyor (tekilleştirme)..."
echo "deb [signed-by=${KEY_FILE}] https://artifacts.elastic.co/packages/9.x/apt stable main" > "${REPO_FILE}"

log "Paket listesi tekrar güncelleniyor..."
apt-get update -y

# ---------- 3) Paketler ----------
log "Elasticsearch kuruluyor..."
apt-get install -y elasticsearch
log "Kibana kuruluyor..."
apt-get install -y kibana
log "Logstash kuruluyor..."
apt-get install -y logstash

# ---------- 4) Kernel parametresi ----------
log "vm.max_map_count ayarlanıyor..."
echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-elasticsearch.conf
sysctl -p /etc/sysctl.d/99-elasticsearch.conf >/dev/null

# ---------- 5) Dizinler & İzinler ----------
log "Dizinler ve izinler düzenleniyor..."
install -d -m 0750 -o elasticsearch -g elasticsearch /var/lib/elasticsearch
install -d -m 0750 -o elasticsearch -g elasticsearch /var/log/elasticsearch

# ---------- 6) systemd drop-in (log & conf yolu) ----------
log "systemd drop-in override yazılıyor..."
mkdir -p /etc/systemd/system/elasticsearch.service.d
cat > /etc/systemd/system/elasticsearch.service.d/override.conf <<'EOF'
[Service]
Environment=ES_LOG_DIR=/var/log/elasticsearch
Environment=ES_PATH_CONF=/etc/elasticsearch
EOF

# ---------- 7) YML dosyalarını SIFIRDAN kopyala ----------
log "YAML dosyaları SIFIRDAN kopyalanıyor (dup. önleme)..."

# Elasticsearch
ES_CONF="/etc/elasticsearch/elasticsearch.yml"
rm -f "${ES_CONF}"
install -m 0640 -o root -g elasticsearch /dev/null "${ES_CONF}"
cat "${REPO_ROOT}/files/elasticsearch/elasticsearch.yml" > "${ES_CONF}"

# Kibana
KB_CONF="/etc/kibana/kibana.yml"
rm -f "${KB_CONF}"
install -m 0644 -o root -g root /dev/null "${KB_CONF}"
cat "${REPO_ROOT}/files/kibana/kibana.yml" > "${KB_CONF}"

# Logstash pipeline (şifreyi sonra yerleştireceğiz)
LS_PIPE="/etc/logstash/conf.d/fortigate.conf"
rm -f "${LS_PIPE}"
install -m 0644 -o root -g root /dev/null "${LS_PIPE}"
cat "${REPO_ROOT}/files/logstash/fortigate.conf" > "${LS_PIPE}"

# JVM heap sabitle (1g)
mkdir -p /etc/elasticsearch/jvm.options.d
cat > /etc/elasticsearch/jvm.options.d/heap.options <<'EOF'
-Xms1g
-Xmx1g
EOF
chmod 0640 /etc/elasticsearch/jvm.options.d/heap.options
chown root:elasticsearch /etc/elasticsearch/jvm.options.d/heap.options

# Sahiplik
chown -R elasticsearch:elasticsearch /etc/elasticsearch
chown -R logstash:logstash /etc/logstash

# ---------- 8) Elasticsearch'i başlat ----------
log "Elasticsearch servisi etkinleştiriliyor ve başlatılıyor..."
systemctl daemon-reload
systemctl enable elasticsearch.service
systemctl restart elasticsearch.service || true

# ES hazır olana kadar bekle (sertifika üretimi için ilk start şart)
log "Elasticsearch başlıyor (maks 120s bekleniyor)..."
for i in $(seq 1 120); do
  if systemctl is-active --quiet elasticsearch.service; then
    # CA sertifikası üretildi mi?
    if [[ -f /etc/elasticsearch/certs/http_ca.crt ]]; then
      # TLS üstünden cevap veriyor mu? (401 bile verse port açık demektir)
      if curl -ks https://localhost:9200 >/dev/null 2>&1; then
        break
      fi
    fi
  fi
  sleep 1
  if [[ $i -eq 120 ]]; then
    journalctl -u elasticsearch.service --no-pager | tail -n 200 >&2
    die "Elasticsearch ayağa kalkmadı."
  fi
done
log "Elasticsearch ayakta."

# ---------- 9) Parolalar (non-interactive reset) ----------
log "elastic ve kibana_system parolaları sıfırlanıyor..."
ELASTIC_PW="$(/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b | awk '/New value:/ {print $NF}')"
KIBANA_SYS_PW="$(/usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -s -b | awk '/New value:/ {print $NF}')"
[[ -n "${ELASTIC_PW:-}" ]] || die "elastic parolası alınamadı."
[[ -n "${KIBANA_SYS_PW:-}" ]] || die "kibana_system parolası alınamadı."
log "Parolalar alındı."

# ---------- 10) Logstash pipeline içine ES şifresini işle ----------
log "Logstash pipeline güncelleniyor (elastic şifresi gömülüyor)..."
# place-holder varsa değiştir
if grep -q 'ES_ELASTIC_PASSWORD' "${LS_PIPE}"; then
  sed -i "s|\${ES_ELASTIC_PASSWORD}|${ELASTIC_PW}|g" "${LS_PIPE}"
fi

# ---------- 11) Kibana & Logstash başlat ----------
log "Kibana servisi etkinleştiriliyor ve başlatılıyor..."
systemctl enable kibana.service
systemctl restart kibana.service

log "Logstash servisi etkinleştiriliyor ve başlatılıyor..."
systemctl enable logstash.service
systemctl restart logstash.service

# ---------- 12) Kibana Enrollment Token ----------
log "Kibana Enrollment Token alınıyor..."
KIBANA_TOKEN="$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana || true)"
if [[ -z "${KIBANA_TOKEN}" ]]; then
  # ES ilk dakikalarda token üretimi için hazır değilse 5sn sonra dene
  sleep 5
  KIBANA_TOKEN="$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana || true)"
fi

IP="$(hostname -I | awk '{print $1}')"
echo
echo "==============================================================="
echo "[+] Kurulum tamamlandı."
echo "Kibana:  http://${IP}:5601"
echo "Elastic kullanıcı adı: elastic"
echo "Elastic parola: ${ELASTIC_PW}"
echo "kibana_system parola (bilgi): ${KIBANA_SYS_PW}"
echo "Kibana Enrollment Token: ${KIBANA_TOKEN}"
echo "==============================================================="