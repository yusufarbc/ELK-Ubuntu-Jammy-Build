#!/usr/bin/env bash
set -euo pipefail

log(){ echo -e "[*] $*"; }
die(){ echo "[-] $*" >&2; exit 1; }
[[ $(id -u) -eq 0 ]] || die "Lütfen sudo/root ile çalıştırın."
export DEBIAN_FRONTEND=noninteractive

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
FILES_DIR="${BASE_DIR}/files"

# ---------- 0) Paketler & depo (idempotent) ----------
log "Paket listesi güncelleniyor..."
apt-get update -y
log "Gerekli bağımlılıklar kuruluyor..."
apt-get install -y curl wget jq unzip apt-transport-https gnupg2

log "Elastic GPG anahtarı ekleniyor (idempotent)..."
KEY_FILE="/usr/share/keyrings/elasticsearch-keyring.gpg"
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor > "${KEY_FILE}.tmp"
install -m 0644 "${KEY_FILE}.tmp" "${KEY_FILE}"; rm -f "${KEY_FILE}.tmp"

log "Elastic deposu (tek satır) yazılıyor..."
REPO_FILE="/etc/apt/sources.list.d/elastic-9.x.list"
echo "deb [signed-by=${KEY_FILE}] https://artifacts.elastic.co/packages/9.x/apt stable main" > "${REPO_FILE}"

log "Paket listesi tekrar güncelleniyor..."
apt-get update -y

log "Elasticsearch kuruluyor..."
apt-get install -y elasticsearch
log "Kibana kuruluyor..."
apt-get install -y kibana
log "Logstash kuruluyor..."
apt-get install -y logstash

# ---------- 1) Kernel & dizin/izinler ----------
log "vm.max_map_count ayarlanıyor..."
echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-elasticsearch.conf
sysctl -p /etc/sysctl.d/99-elasticsearch.conf >/dev/null

log "Dizinler ve izinler düzenleniyor..."
install -d -m 0750 -o elasticsearch -g elasticsearch /var/lib/elasticsearch
install -d -m 0750 -o elasticsearch -g elasticsearch /var/log/elasticsearch
install -d -m 0750 -o elasticsearch -g elasticsearch /etc/elasticsearch/certs

# ---------- 2) systemd drop-in (log ve conf yolu garanti) ----------
log "systemd drop-in override yazılıyor..."
mkdir -p /etc/systemd/system/elasticsearch.service.d
cat >/etc/systemd/system/elasticsearch.service.d/override.conf <<'EOF'
[Service]
Environment=ES_LOG_DIR=/var/log/elasticsearch
Environment=ES_PATH_CONF=/etc/elasticsearch
EOF

# ---------- 3) TLS: CA + HTTP/Transport (PEM) ----------
log "TLS CA ve HTTP/Transport sertifikaları (PEM) oluşturuluyor..."
CA_P12="/etc/elasticsearch/certs/elastic-stack-ca.p12"
/usr/share/elasticsearch/bin/elasticsearch-certutil ca --silent --out "${CA_P12}" --pass ""

# CA PEM (Kibana/Logstash kullanacak)
openssl pkcs12 -in "${CA_P12}" -nokeys -passin pass: -out /etc/elasticsearch/certs/ca.crt >/dev/null 2>&1
chown elasticsearch:elasticsearch /etc/elasticsearch/certs/ca.crt
chmod 0640 /etc/elasticsearch/certs/ca.crt

# SAN’lar: localhost, 127.0.0.1, IP, FQDN
IP="$(hostname -I | awk '{print $1}')"
FQDN="$(hostname -f 2>/dev/null || hostname)"
cat >/etc/elasticsearch/certs/instances.yml <<EOF
instances:
  - name: http
    dns: [ "localhost", "${FQDN}" ]
    ip:  [ "127.0.0.1", "${IP}" ]
  - name: transport
    dns: [ "localhost" ]
    ip:  [ "127.0.0.1" ]
EOF
chown elasticsearch:elasticsearch /etc/elasticsearch/certs/instances.yml
chmod 0640 /etc/elasticsearch/certs/instances.yml

# HTTP cert/key PEM
HTTP_ZIP="/etc/elasticsearch/certs/http.zip"
/usr/share/elasticsearch/bin/elasticsearch-certutil cert --silent --ca "${CA_P12}" --ca-pass "" \
  --pem --in /etc/elasticsearch/certs/instances.yml --out "${HTTP_ZIP}"
unzip -o "${HTTP_ZIP}" -d /etc/elasticsearch/certs >/dev/null
crt="$(find /etc/elasticsearch/certs -type f -name "*.crt" | grep /http/ | head -n1)"
key="$(find /etc/elasticsearch/certs -type f -name "*.key" | grep /http/ | head -n1)"
mv -f "$crt" /etc/elasticsearch/certs/http.crt
mv -f "$key" /etc/elasticsearch/certs/http.key
rm -rf /etc/elasticsearch/certs/http "${HTTP_ZIP}"
chown elasticsearch:elasticsearch /etc/elasticsearch/certs/http.crt /etc/elasticsearch/certs/http.key
chmod 0640 /etc/elasticsearch/certs/http.crt /etc/elasticsearch/certs/http.key

# Transport cert/key PEM
TRANS_ZIP="/etc/elasticsearch/certs/transport.zip"
/usr/share/elasticsearch/bin/elasticsearch-certutil cert --silent --ca "${CA_P12}" --ca-pass "" \
  --name transport --dns localhost --ip 127.0.0.1 --pem --out "${TRANS_ZIP}"
unzip -o "${TRANS_ZIP}" -d /etc/elasticsearch/certs >/dev/null
tcrt="$(find /etc/elasticsearch/certs -type f -name "*.crt" | grep /transport/ | head -n1)"
tkey="$(find /etc/elasticsearch/certs -type f -name "*.key" | grep /transport/ | head -n1)"
mv -f "$tcrt" /etc/elasticsearch/certs/transport.crt
mv -f "$tkey" /etc/elasticsearch/certs/transport.key
rm -rf /etc/elasticsearch/certs/transport "${TRANS_ZIP}"
chown elasticsearch:elasticsearch /etc/elasticsearch/certs/transport.crt /etc/elasticsearch/certs/transport.key
chmod 0640 /etc/elasticsearch/certs/transport.crt /etc/elasticsearch/certs/transport.key

# ---------- 4) YAML dosyaları REPODAN kopyala (SIFIRDAN) ----------
log "YAML dosyaları SIFIRDAN kopyalanıyor..."
install -m 0640 -o elasticsearch -g elasticsearch "${FILES_DIR}/elasticsearch/elasticsearch.yml" /etc/elasticsearch/elasticsearch.yml
install -m 0644 -o kibana        -g kibana        "${FILES_DIR}/kibana/kibana.yml"           /etc/kibana/kibana.yml
install -m 0644 "${FILES_DIR}/logstash/fortigate.conf" /etc/logstash/conf.d/fortigate.conf

# ---------- 5) Elasticsearch başlat & health ----------
log "Elasticsearch servisi etkinleştiriliyor ve başlatılıyor..."
systemctl daemon-reload
systemctl enable elasticsearch.service
systemctl restart elasticsearch.service || true

log "Elasticsearch başlıyor (maks 150s bekleniyor)..."
for i in $(seq 1 150); do
  if curl -s --cacert /etc/elasticsearch/certs/ca.crt https://localhost:9200 >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if [[ $i -eq 150 ]]; then
    journalctl -u elasticsearch.service --no-pager | tail -n 200 >&2
    die "Elasticsearch ayağa kalkmadı."
  fi
done
log "Elasticsearch ayakta."

# ---------- 6) elastic parolası sıfırla ----------
log "elastic parolası sıfırlanıyor..."
ELASTIC_PW="$(/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b | awk '/New value:/ {print $NF}')"
[[ -n "${ELASTIC_PW}" ]] || die "elastic parolası alınamadı."

# Logstash keystore’a şifreyi güvenli koy (fortigate.conf dosyasını değiştirmiyoruz)
log "Logstash keystore'a ES parolası yazılıyor..."
/usr/share/logstash/bin/logstash-keystore create --force >/dev/null 2>&1 || true
echo "${ELASTIC_PW}" | /usr/share/logstash/bin/logstash-keystore add ES_PW --stdin --force

# ---------- 7) Kibana & Logstash ----------
log "Kibana servisi etkinleştiriliyor ve başlatılıyor..."
systemctl enable kibana.service
systemctl restart kibana.service

log "Logstash servisi etkinleştiriliyor ve başlatılıyor..."
systemctl enable logstash.service
systemctl restart logstash.service

# ---------- 8) Enrollment token ----------
log "Kibana Enrollment Token alınıyor..."
KIBANA_TOKEN="$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana || true)"
if [[ -z "${KIBANA_TOKEN}" ]]; then
  sleep 3
  KIBANA_TOKEN="$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana || true)"
fi

IP_PRINT="${IP}"
echo
echo "==============================================================="
echo "[+] Kurulum tamamlandı."
echo "Kibana:  http://${IP_PRINT}:5601"
echo "Elastic kullanıcı adı: elastic"
echo "Elastic parola: ${ELASTIC_PW}"
echo "Kibana Enrollment Token: ${KIBANA_TOKEN}"
echo "Not: FortiGate/Beats için Logstash dinliyor: 0.0.0.0:5044"
echo "==============================================================="