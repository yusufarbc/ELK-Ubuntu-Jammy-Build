#!/usr/bin/env bash
set -euo pipefail

log(){ echo -e "[*] $*"; }
die(){ echo "[-] $*" >&2; exit 1; }
[[ $(id -u) -eq 0 ]] || die "Lütfen sudo/root ile çalıştırın."
export DEBIAN_FRONTEND=noninteractive

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
ES_YML_SRC="${REPO_DIR}/files/elasticsearch/elasticsearch.yml"
KB_YML_SRC="${REPO_DIR}/files/kibana/kibana.yml"
LS_CONF_SRC="${REPO_DIR}/files/logstash/fortigate.conf"

# ------------------------------------------------------------
# 1) Bağımlılıklar ve Elastic depo
# ------------------------------------------------------------
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

# ------------------------------------------------------------
# 2) Kernel param, dizin-izin ve systemd override
# ------------------------------------------------------------
log "vm.max_map_count ayarlanıyor..."
echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-elasticsearch.conf
sysctl -p /etc/sysctl.d/99-elasticsearch.conf >/dev/null

log "Dizinler ve izinler düzenleniyor..."
install -d -m 0750 -o elasticsearch -g elasticsearch /var/lib/elasticsearch
install -d -m 0750 -o elasticsearch -g elasticsearch /var/log/elasticsearch
install -d -m 0750 -o elasticsearch -g elasticsearch /etc/elasticsearch/certs

log "systemd drop-in override yazılıyor..."
install -d /etc/systemd/system/elasticsearch.service.d
cat >/etc/systemd/system/elasticsearch.service.d/override.conf <<'EOF'
[Service]
Environment=ES_LOG_DIR=/var/log/elasticsearch
Environment=ES_PATH_CONF=/etc/elasticsearch
EOF

systemctl daemon-reload

# ------------------------------------------------------------
# 3) Sertifikalar: CA + HTTP + Transport (PEM) ve geniş SAN
# ------------------------------------------------------------
log "TLS CA ve HTTP/Transport sertifikaları (PEM) oluşturuluyor..."

ES_CERT_DIR="/etc/elasticsearch/certs"
pushd "${ES_CERT_DIR}" >/dev/null

# CA (PEM)
if [[ ! -f ca/ca.crt || ! -f ca/ca.key ]]; then
  rm -rf ca ca.zip
  /usr/share/elasticsearch/bin/elasticsearch-certutil ca --pem --out ca.zip
  unzip -qo ca.zip -d .
  rm -f ca.zip
fi

# Makine kimlikleri
HOST_SHORT="$(hostname -s || echo localhost)"
HOST_FQDN="$(hostname -f || echo ${HOST_SHORT})"

# Tüm non-loopback IP'ler
IPS=()
while read -r ip; do
  [[ -z "$ip" ]] && continue
  [[ "$ip" == 127.* ]] && continue
  IPS+=("$ip")
done < <(hostname -I 2>/dev/null | tr ' ' '\n')

# HTTP sertifikası
if [[ ! -f http.crt || ! -f http.key ]]; then
  rm -rf http http.zip
  # --dns ve --ip parametrelerini çoklayarak geçiyoruz
  DNS_ARGS=(--dns localhost --dns "${HOST_SHORT}" --dns "${HOST_FQDN}")
  IP_ARGS=(--ip 127.0.0.1)
  for ip in "${IPS[@]}"; do IP_ARGS+=(--ip "$ip"); done

  /usr/share/elasticsearch/bin/elasticsearch-certutil cert \
    --name http --pem \
    --ca-cert ca/ca.crt --ca-key ca/ca.key \
    "${DNS_ARGS[@]}" "${IP_ARGS[@]}" \
    --out http.zip

  unzip -qo http.zip -d http
  # çıktı: http/http.crt ve http/http.key
  install -m 0640 -o elasticsearch -g elasticsearch http/http.crt http.crt
  install -m 0640 -o elasticsearch -g elasticsearch http/http.key http.key
  rm -rf http http.zip
fi

# Transport sertifikası
if [[ ! -f transport.crt || ! -f transport.key ]]; then
  rm -rf transport transport.zip
  DNS_ARGS=(--dns "${HOST_SHORT}" --dns "${HOST_FQDN}")
  IP_ARGS=(--ip 127.0.0.1)
  for ip in "${IPS[@]}"; do IP_ARGS+=(--ip "$ip"); done

  /usr/share/elasticsearch/bin/elasticsearch-certutil cert \
    --name transport --pem \
    --ca-cert ca/ca.crt --ca-key ca/ca.key \
    "${DNS_ARGS[@]}" "${IP_ARGS[@]}" \
    --out transport.zip

  unzip -qo transport.zip -d transport
  install -m 0640 -o elasticsearch -g elasticsearch transport/transport.crt transport.crt
  install -m 0640 -o elasticsearch -g elasticsearch transport/transport.key transport.key
  rm -rf transport transport.zip
fi

# CA'yı da world-readable yapmayın; yalnızca gerekli servisler okuyacak
install -m 0644 -o root -g elasticsearch ca/ca.crt ca.crt
chown -R elasticsearch:elasticsearch "${ES_CERT_DIR}"

popd >/dev/null

# ------------------------------------------------------------
# 4) YAML dosyalarını SIFIRDAN kopyala (duplikasyon yok)
# ------------------------------------------------------------
log "YAML dosyaları SIFIRDAN kopyalanıyor..."
install -m 0644 -o elasticsearch -g elasticsearch "${ES_YML_SRC}" /etc/elasticsearch/elasticsearch.yml
install -m 0644 -o root -g kibana        "${KB_YML_SRC}" /etc/kibana/kibana.yml
install -m 0644 -o root -g root          "${LS_CONF_SRC}" /etc/logstash/conf.d/fortigate.conf

# ------------------------------------------------------------
# 5) Elasticsearch: enable+start ve sağlık
# ------------------------------------------------------------
log "Elasticsearch servisi etkinleştiriliyor ve başlatılıyor..."
systemctl enable --now elasticsearch.service

log "Elasticsearch başlıyor (maks 150s bekleniyor)..."
CA="/etc/elasticsearch/certs/ca.crt"
for i in $(seq 1 150); do
  if curl -s --cacert "$CA" https://localhost:9200 >/dev/null 2>&1; then
    log "Elasticsearch ayakta."
    break
  fi
  sleep 1
  [[ $i -eq 150 ]] && { journalctl -u elasticsearch --no-pager | tail -n 200 >&2; die "Elasticsearch ayağa kalkmadı."; }
done

# ------------------------------------------------------------
# 6) Şifreler ve kullanıcılar (hostname/SAN artık eşleşiyor)
# ------------------------------------------------------------
log "elastic parolası sıfırlanıyor..."
ELASTIC_PW="$(/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b | awk '/New value:/ {print $NF}')"
[[ -n "${ELASTIC_PW:-}" ]] || die "elastic parolası alınamadı."

# Logstash için minimal role + user
log "Logstash role ve user oluşturuluyor..."
curl -sk --cacert "$CA" -u "elastic:${ELASTIC_PW}" \
  -X PUT "https://localhost:9200/_security/role/logstash_writer" \
  -H 'Content-Type: application/json' -d '{
    "cluster": ["monitor"],
    "indices": [
      { "names": ["fortigate-logs-*"], "privileges": ["create_index","write","create_doc","auto_configure","view_index_metadata"] }
    ]
  }' >/dev/null

# güçlü parola üret
LOGSTASH_PW="$(openssl rand -base64 24)"
curl -sk --cacert "$CA" -u "elastic:${ELASTIC_PW}" \
  -X POST "https://localhost:9200/_security/user/logstash_ingest" \
  -H 'Content-Type: application/json' -d "{
    \"password\" : \"${LOGSTASH_PW}\",
    \"roles\" : [\"logstash_writer\"],
    \"full_name\" : \"Logstash Ingest\",
    \"enabled\": true
  }" >/dev/null || true

# ------------------------------------------------------------
# 7) Logstash keystore’a ES parolasını gizle
# ------------------------------------------------------------
log "Logstash keystore hazırlanıyor..."
/usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash create 2>/dev/null || true
echo -n "${LOGSTASH_PW}" | /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash add --stdin ES_PW >/dev/null

# ------------------------------------------------------------
# 8) Kibana enable+start ve Enrollment Token
# ------------------------------------------------------------
log "Kibana servisi etkinleştiriliyor ve başlatılıyor..."
systemctl enable --now kibana.service || true

log "Kibana Enrollment Token alınıyor..."
KIBANA_TOKEN="$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana || true)"

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
: "${IP:=127.0.0.1}"

echo
echo "==============================================================="
echo "[+] Kurulum tamamlandı."
echo "Kibana:  http://${IP}:5601"
echo "Elastic   kullanıcı adı: elastic"
echo "Elastic   parola       : ${ELASTIC_PW}"
echo "Logstash  kullanıcı    : logstash_ingest"
echo "Logstash  parola       : ${LOGSTASH_PW}"
echo "Kibana Enrollment Token: ${KIBANA_TOKEN}"
echo "CA (Kibana/Logstash için): /etc/elasticsearch/certs/ca.crt"
echo "==============================================================="