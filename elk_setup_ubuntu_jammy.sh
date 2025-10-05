#!/usr/bin/env bash
set -euo pipefail

log(){ echo -e "[*] $*"; }
die(){ echo -e "[-] $*" >&2; exit 1; }
[[ $(id -u) -eq 0 ]] || die "Lütfen sudo/root ile çalıştırın."
export DEBIAN_FRONTEND=noninteractive
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

# -------- 1) Bağımlılıklar + Elastic repo (idempotent) --------
log "Paket listesi güncelleniyor..."
apt-get update -y
log "Gerekli bağımlılıklar kuruluyor..."
apt-get install -y curl wget jq unzip apt-transport-https gnupg2

KEY_FILE="/usr/share/keyrings/elasticsearch-keyring.gpg"
REPO_FILE="/etc/apt/sources.list.d/elastic-9.x.list"
log "Elastic GPG anahtarı ekleniyor (idempotent)..."
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor > "${KEY_FILE}.tmp"
install -m 0644 "${KEY_FILE}.tmp" "${KEY_FILE}"; rm -f "${KEY_FILE}.tmp"
log "Elastic deposu tek satır olarak yazılıyor..."
echo "deb [signed-by=${KEY_FILE}] https://artifacts.elastic.co/packages/9.x/apt stable main" > "${REPO_FILE}"

log "Paket listesi tekrar güncelleniyor..."
apt-get update -y

# -------- 2) Paketler --------
log "Elasticsearch kuruluyor..."
apt-get install -y elasticsearch
log "Kibana kuruluyor..."
apt-get install -y kibana
log "Logstash kuruluyor..."
apt-get install -y logstash

# -------- 3) Kernel parametresi --------
log "vm.max_map_count ayarlanıyor..."
echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-elasticsearch.conf
sysctl -p /etc/sysctl.d/99-elasticsearch.conf >/dev/null

# -------- 4) Dizinler & izinler --------
log "Dizinler ve izinler düzenleniyor..."
install -d -m 0750 -o elasticsearch -g elasticsearch /var/lib/elasticsearch
install -d -m 0750 -o elasticsearch -g elasticsearch /var/log/elasticsearch
install -d -m 0750 -o elasticsearch -g elasticsearch /etc/elasticsearch/certs

# -------- 5) systemd drop-in (log & conf yolu) --------
log "systemd drop-in override yazılıyor..."
mkdir -p /etc/systemd/system/elasticsearch.service.d
cat > /etc/systemd/system/elasticsearch.service.d/override.conf <<'EOF'
[Service]
Environment=ES_LOG_DIR=/var/log/elasticsearch
Environment=ES_PATH_CONF=/etc/elasticsearch
EOF

# -------- 6) YML'leri SIFIRDAN kopyala (dup yok) --------
log "YAML dosyaları SIFIRDAN kopyalanıyor..."
ES_CONF="/etc/elasticsearch/elasticsearch.yml"
KB_CONF="/etc/kibana/kibana.yml"
LS_PIPE="/etc/logstash/conf.d/fortigate.conf"

install -D -m 0640 -o root -g elasticsearch /dev/null "${ES_CONF}"
cat "${REPO_ROOT}/files/elasticsearch/elasticsearch.yml" > "${ES_CONF}"

install -D -m 0644 -o root -g root /dev/null "${KB_CONF}"
cat "${REPO_ROOT}/files/kibana/kibana.yml" > "${KB_CONF}"

install -D -m 0644 -o root -g root /dev/null "${LS_PIPE}"
cat "${REPO_ROOT}/files/logstash/fortigate.conf" > "${LS_PIPE}"

# JVM heap (1g)
mkdir -p /etc/elasticsearch/jvm.options.d
cat > /etc/elasticsearch/jvm.options.d/heap.options <<'EOF'
-Xms1g
-Xmx1g
EOF
chmod 0640 /etc/elasticsearch/jvm.options.d/heap.options
chown root:elasticsearch /etc/elasticsearch/jvm.options.d/heap.options

# -------- 7) TLS: CA + HTTP & TRANSPORT sertifikaları (PEM) --------
log "TLS CA ve HTTP/Transport sertifikaları (PEM) oluşturuluyor..."

# 7.1) CA (PKCS12)
CA_P12="/etc/elasticsearch/certs/elastic-stack-ca.p12"
/usr/share/elasticsearch/bin/elasticsearch-certutil ca \
  --silent \
  --out "${CA_P12}" \
  --pass ""

# 7.2) CA'yı PEM'e dönüştür (ca.crt)
openssl pkcs12 -in "${CA_P12}" -nokeys -passin pass: -out /etc/elasticsearch/certs/ca.crt >/dev/null 2>&1

# 7.3) HTTP sertifikası (PEM zip üret, unzip et)
HTTP_ZIP="/etc/elasticsearch/certs/http.zip"
/usr/share/elasticsearch/bin/elasticsearch-certutil cert \
  --silent \
  --ca "${CA_P12}" \
  --ca-pass "" \
  --name http \
  --dns localhost \
  --ip 127.0.0.1 \
  --pem \
  --out "${HTTP_ZIP}"

unzip -o "${HTTP_ZIP}" -d /etc/elasticsearch/certs >/dev/null
# Çıkan dizin genelde 'http/' olur:
if [[ -f /etc/elasticsearch/certs/http/http.crt && -f /etc/elasticsearch/certs/http/http.key ]]; then
  mv -f /etc/elasticsearch/certs/http/http.crt /etc/elasticsearch/certs/http.crt
  mv -f /etc/elasticsearch/certs/http/http.key /etc/elasticsearch/certs/http.key
  rm -rf /etc/elasticsearch/certs/http
fi

# 7.4) Transport (node) sertifikası (PEM)
TRANS_ZIP="/etc/elasticsearch/certs/transport.zip"
/usr/share/elasticsearch/bin/elasticsearch-certutil cert \
  --silent \
  --ca "${CA_P12}" \
  --ca-pass "" \
  --name transport \
  --dns localhost \
  --ip 127.0.0.1 \
  --pem \
  --out "${TRANS_ZIP}"

unzip -o "${TRANS_ZIP}" -d /etc/elasticsearch/certs >/dev/null
# Çıkan dosyalar genelde 'transport/transport.crt|key' ya da 'transport/transport-*.crt' olur:
if [[ -f /etc/elasticsearch/certs/transport/transport.crt && -f /etc/elasticsearch/certs/transport/transport.key ]]; then
  mv -f /etc/elasticsearch/certs/transport/transport.crt /etc/elasticsearch/certs/transport.crt
  mv -f /etc/elasticsearch/certs/transport/transport.key /etc/elasticsearch/certs/transport.key
else
  # Tek dosya ismi farklıysa ilk .crt ve .key'i al
  crt="$(ls /etc/elasticsearch/certs/transport/*.crt | head -n1 || true)"
  key="$(ls /etc/elasticsearch/certs/transport/*.key | head -n1 || true)"
  [[ -n "${crt}" && -n "${key}" ]] && mv -f "${crt}" /etc/elasticsearch/certs/transport.crt && mv -f "${key}" /etc/elasticsearch/certs/transport.key
fi
rm -rf /etc/elasticsearch/certs/transport

# Sahiplik/izin
chown -R elasticsearch:elasticsearch /etc/elasticsearch/certs
chmod 0640 /etc/elasticsearch/certs/* || true

# -------- 8) Elasticsearch’i başlat ve bekle --------
log "Elasticsearch servisi etkinleştiriliyor ve başlatılıyor..."
systemctl daemon-reload
systemctl enable elasticsearch.service
systemctl restart elasticsearch.service || true

log "Elasticsearch başlıyor (maks 150s bekleniyor)..."
ok=false
for i in $(seq 1 150); do
  if systemctl is-active --quiet elasticsearch.service; then
    if curl -ks https://localhost:9200 >/dev/null 2>&1; then
      ok=true; break
    fi
  fi
  sleep 1
done

if [[ "${ok}" != true ]]; then
  echo "---- /var/log/elasticsearch/elasticsearch.log (son 200 satır) ----" >&2
  tail -n 200 /var/log/elasticsearch/elasticsearch.log >&2 || true
  die "Elasticsearch ayağa kalkmadı."
fi
log "Elasticsearch ayakta."

# -------- 9) Parolaları non-interactive resetle --------
log "elastic ve kibana_system parolaları sıfırlanıyor..."
ELASTIC_PW="$(/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b | awk '/New value:/ {print $NF}')"
KIBANA_SYS_PW="$(/usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -s -b | awk '/New value:/ {print $NF}')"
[[ -n "${ELASTIC_PW:-}" ]] || die "elastic parolası alınamadı."
[[ -n "${KIBANA_SYS_PW:-}" ]] || die "kibana_system parolası alınamadı."
log "Parolalar alındı."

# Logstash pipeline içine şifreyi işle
log "Logstash pipeline güncelleniyor (elastic şifresi gömülüyor)..."
sed -i "s|\${ES_ELASTIC_PASSWORD}|${ELASTIC_PW}|g" "${LS_PIPE}"

# -------- 10) Kibana & Logstash --------
log "Kibana servisi etkinleştiriliyor ve başlatılıyor..."
systemctl enable kibana.service
systemctl restart kibana.service

log "Logstash servisi etkinleştiriliyor ve başlatılıyor..."
systemctl enable logstash.service
systemctl restart logstash.service

# -------- 11) Kibana Enrollment Token --------
log "Kibana Enrollment Token alınıyor..."
KIBANA_TOKEN="$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana || true)"
if [[ -z "${KIBANA_TOKEN}" ]]; then
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