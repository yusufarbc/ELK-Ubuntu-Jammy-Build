#!/usr/bin/env bash
# =============================================================================
#  ELK Stack (Elasticsearch, Logstash, Kibana) Otomatik Kurulum Betiği
#  Hedef: Ubuntu 22.04 (Jammy)
#
#  Özellikler:
#   - Tek komutla kurulum (ES, Kibana, Logstash)
#   - APT repo + GPG key (signed-by) temiz/tekil ekleme
#   - vm.max_map_count ayarı
#   - ES sadece localhost:9200 (TLS etkin)
#   - Kibana 0.0.0.0:5601, Logstash Beats 0.0.0.0:5044 (dışa açık)
#   - Sertifikalar: CA + HTTP + Transport (PEM), geniş SAN (127.0.0.1, localhost, hostname, FQDN, tüm non-loopback IP’ler)
#   - ES için systemd drop-in (ES_LOG_DIR, ES_PATH_CONF)
#   - elastic parolasını otomatik sıfırlama (reset-password) ve terminale yazdırma
#   - Kibana enrollment token otomatik üretimi ve terminale yazdırma
#   - Logstash için özel rol+user (logstash_ingest) ve güçlü parola; parola Logstash keystore’a yazılır
#   - Sağlık kontrolleri ve idempotent çalışma
#
#  Kullanım:
#    sudo bash elk_setup_ubuntu_jammy.sh
#
#  Dizin düzeni (repo kökü):
#    ./elk_setup_ubuntu_jammy.sh
#    ./files/
#      ├─ elasticsearch/elasticsearch.yml
#      ├─ kibana/kibana.yml
#      └─ logstash/fortigate.conf
# =============================================================================

set -Eeuo pipefail

# ---- Genel değişkenler -------------------------------------------------------
ES_VER="8.x"                                       # Elastic 8.x apt deposu
ARCH="$(dpkg --print-architecture)"                # amd64/arm64 vb.
APT_LIST="/etc/apt/sources.list.d/elastic-${ES_VER}.list"
KEYRING_DIR="/etc/apt/keyrings"
ELASTIC_KEY="${KEYRING_DIR}/elastic.gpg"

ES_CONF_DIR="/etc/elasticsearch"
ES_DATA_DIR="/var/lib/elasticsearch"
ES_LOG_DIR="/var/log/elasticsearch"
ES_CERT_DIR="${ES_CONF_DIR}/certs"
ES_CA_CRT="${ES_CERT_DIR}/ca.crt"
ES_CA_KEY="${ES_CERT_DIR}/ca.key"
ES_HTTP_CRT="${ES_CERT_DIR}/http.crt"
ES_HTTP_KEY="${ES_CERT_DIR}/http.key"
ES_TRANS_CRT="${ES_CERT_DIR}/transport.crt"
ES_TRANS_KEY="${ES_CERT_DIR}/transport.key"

ES_BIN_DIR="/usr/share/elasticsearch/bin"
ES_SERVICE="elasticsearch"
KIBANA_SERVICE="kibana"
LOGSTASH_SERVICE="logstash"

KIBANA_PORT=5601
LOGSTASH_BEATS_PORT=5044

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILES_DIR="${REPO_ROOT}/files"

LOGSTASH_KEYSTORE="/etc/logstash/logstash.keystore"
LOGSTASH_CERT_DIR="/etc/logstash/certs"
LOGSTASH_ES_CA="${LOGSTASH_CERT_DIR}/ca.crt"

# ---- Yardımcı çıktılar -------------------------------------------------------
msg() { echo -e "\e[1;32m[+]\e[0m $*"; }
warn() { echo -e "\e[1;33m[!]\e[0m $*"; }
err() { echo -e "\e[1;31m[-]\e[0m $*"; }

trap 'err "Bir hata oluştu (satır: $LINENO). Günlük ve terminal çıktısını kontrol edin."' ERR

# ---- Kök (root) kontrolü -----------------------------------------------------
require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "Bu betiği root olarak çalıştırın (sudo)."
    exit 1
  fi
}

# ---- APT repo & bağımlılıklar ------------------------------------------------
setup_repo_and_prereqs() {
  msg "APT bağımlılıkları ve Elastic deposu hazırlanıyor..."

  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    apt-transport-https ca-certificates curl wget jq unzip gpg lsb-release coreutils

  # Keyring dizini yoksa oluştur
  install -d -m 0755 "${KEYRING_DIR}"

  # Elastic GPG anahtarı: signed-by yöntemi ile tekil keyring
  if [[ ! -f "${ELASTIC_KEY}" ]]; then
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o "${ELASTIC_KEY}"
    chmod 0644 "${ELASTIC_KEY}"
    msg "Elastic GPG anahtarı eklendi: ${ELASTIC_KEY}"
  else
    msg "Elastic GPG anahtarı zaten mevcut."
  fi

  # Eski/duplike depo kayıtlarını temizle (ihtiyaten)
  if grep -Rqs "artifacts.elastic.co" /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null; then
    sed -i '/artifacts.elastic.co/d' /etc/apt/sources.list || true
    find /etc/apt/sources.list.d -type f -name "*.list" -exec sed -i '/artifacts.elastic.co/d' {} \; || true
  fi

  # Yeni depo kaydı
  echo "deb [signed-by=${ELASTIC_KEY} arch=${ARCH}] https://artifacts.elastic.co/packages/${ES_VER}/apt stable main" > "${APT_LIST}"
  chmod 0644 "${APT_LIST}"

  apt-get update -y
  msg "APT deposu ve bağımlılıklar hazır."
}

# ---- vm.max_map_count --------------------------------------------------------
tune_sysctl() {
  msg "vm.max_map_count ayarlanıyor..."
  local SYSCTL_FILE="/etc/sysctl.d/99-elastic.conf"
  if [[ ! -f "${SYSCTL_FILE}" ]] || ! grep -q "vm.max_map_count" "${SYSCTL_FILE}"; then
    echo "vm.max_map_count=262144" > "${SYSCTL_FILE}"
  fi
  sysctl --system >/dev/null
  msg "vm.max_map_count=262144 etkin."
}

# ---- Paketler ----------------------------------------------------------------
install_packages() {
  msg "Elasticsearch, Kibana ve Logstash kuruluyor..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y elasticsearch kibana logstash
  msg "Paket kurulumu tamam."
}

# ---- Dizinler & izinler ------------------------------------------------------
prepare_dirs() {
  msg "Konfig ve sertifika dizinleri hazırlanıyor..."
  install -d -m 0750 "${ES_CERT_DIR}"
  chown root:elasticsearch "${ES_CERT_DIR}"

  install -d -m 0755 "${LOGSTASH_CERT_DIR}"

  # ES log ve data dizinleri (paketler zaten oluşturur ama güvence altına alıyoruz)
  install -d -m 0750 "${ES_LOG_DIR}" "${ES_DATA_DIR}" || true
  chown -R elasticsearch:elasticsearch "${ES_LOG_DIR}" "${ES_DATA_DIR}" || true

  msg "Dizinler hazır."
}

# ---- systemd drop-in (ES_LOG_DIR / ES_PATH_CONF) -----------------------------
systemd_dropin_es() {
  msg "systemd drop-in ile ES ortam değişkenleri sabitleniyor..."
  local DROP_DIR="/etc/systemd/system/elasticsearch.service.d"
  local DROP_FILE="${DROP_DIR}/override.conf"
  install -d -m 0755 "${DROP_DIR}"
  cat > "${DROP_FILE}" <<EOF
[Service]
Environment="ES_PATH_CONF=${ES_CONF_DIR}"
Environment="ES_LOG_DIR=${ES_LOG_DIR}"
EOF
  systemctl daemon-reload
  msg "systemd drop-in tamam."
}

# ---- SAN listesi topla (hostname, FQDN, IP’ler) ------------------------------
collect_sans() {
  HOST_SHORT="$(hostname -s)"
  HOST_FQDN="$(hostname -f 2>/dev/null || echo "${HOST_SHORT}")"
  # Tüm non-loopback IP’ler
  mapfile -t IPS < <(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9a-fA-F:.]+$' | sed '/^$/d' || true)

  # global değişkenlere yaz
  SAN_DNS=("localhost" "${HOST_SHORT}" "${HOST_FQDN}")
  SAN_IP=("127.0.0.1" "::1")
  for ip in "${IPS[@]:-}"; do
    [[ "${ip}" == "127.0.0.1" || "${ip}" == "::1" ]] && continue
    SAN_IP+=("${ip}")
  done
}

# ---- Sertifika üretimi (CA + HTTP + Transport) -------------------------------
generate_certs() {
  msg "TLS sertifikaları üretiliyor (CA + HTTP + Transport)..."
  collect_sans

  # CA zaten yoksa üret
  if [[ ! -f "${ES_CA_CRT}" || ! -f "${ES_CA_KEY}" ]]; then
    "${ES_BIN_DIR}/elasticsearch-certutil" ca --silent --pem --out "${ES_CERT_DIR}/ca.zip"
    unzip -o "${ES_CERT_DIR}/ca.zip" -d "${ES_CERT_DIR}/ca" >/dev/null
    # Çıkan dosya adları değişken olabilir; bulup standart isimlere taşı
    local FOUND_CA_CRT
    FOUND_CA_CRT="$(find "${ES_CERT_DIR}/ca" -maxdepth 2 -name '*.crt' | head -n1)"
    local FOUND_CA_KEY
    FOUND_CA_KEY="$(find "${ES_CERT_DIR}/ca" -maxdepth 2 -name '*.key' | head -n1)"
    cp -f "${FOUND_CA_CRT}" "${ES_CA_CRT}"
    cp -f "${FOUND_CA_KEY}" "${ES_CA_KEY}"
    chmod 0640 "${ES_CA_KEY}"
    chown root:elasticsearch "${ES_CA_KEY}" "${ES_CA_CRT}"
  else
    msg "CA zaten mevcut, atlanıyor."
  fi

  # instances.yml dosyalarını oluştur (HTTP ve Transport için)
  local INST_HTTP="${ES_CERT_DIR}/instances_http.yml"
  local INST_TRANS="${ES_CERT_DIR}/instances_transport.yml"

  {
    echo "instances:"
    echo "  - name: es-http"
    echo -n "    dns: ["
    local first=1
    for d in "${SAN_DNS[@]}"; do
      [[ $first -eq 1 ]] && first=0 || echo -n ", "
      echo -n "\"${d}\""
    done
    echo "]"
    echo -n "    ip: ["
    first=1
    for i in "${SAN_IP[@]}"; do
      [[ $first -eq 1 ]] && first=0 || echo -n ", "
      echo -n "\"${i}\""
    done
    echo "]"
  } > "${INST_HTTP}"

  {
    echo "instances:"
    echo "  - name: $(hostname -s)"
    echo -n "    dns: ["
    local first=1
    for d in "${SAN_DNS[@]}"; do
      [[ $first -eq 1 ]] && first=0 || echo -n ", "
      echo -n "\"${d}\""
    done
    echo "]"
    echo -n "    ip: ["
    first=1
    for i in "${SAN_IP[@]}"; do
      [[ $first -eq 1 ]] && first=0 || echo -n ", "
      echo -n "\"${i}\""
    done
    echo "]"
  } > "${INST_TRANS}"

  # HTTP sertifikası (PEM)
  if [[ ! -f "${ES_HTTP_CRT}" || ! -f "${ES_HTTP_KEY}" ]]; then
    "${ES_BIN_DIR}/elasticsearch-certutil" http --silent --pem \
      --in "${INST_HTTP}" \
      --out "${ES_CERT_DIR}/http.zip" \
      --ca-cert "${ES_CA_CRT}" --ca-key "${ES_CA_KEY}"
    unzip -o "${ES_CERT_DIR}/http.zip" -d "${ES_CERT_DIR}/http" >/dev/null
    # Bulunan pem/key'leri standart isimlere taşı
    local FOUND_HTTP_CRT
    FOUND_HTTP_CRT="$(find "${ES_CERT_DIR}/http" -type f -name '*.crt' | head -n1)"
    local FOUND_HTTP_KEY
    FOUND_HTTP_KEY="$(find "${ES_CERT_DIR}/http" -type f -name '*.key' | head -n1)"
    cp -f "${FOUND_HTTP_CRT}" "${ES_HTTP_CRT}"
    cp -f "${FOUND_HTTP_KEY}" "${ES_HTTP_KEY}"
    chmod 0640 "${ES_HTTP_KEY}"
    chown root:elasticsearch "${ES_HTTP_KEY}" "${ES_HTTP_CRT}"
  else
    msg "HTTP sertifikası zaten mevcut, atlanıyor."
  fi

  # Transport sertifikası (PEM) – single-node olsa da transport ssl açık
  if [[ ! -f "${ES_TRANS_CRT}" || ! -f "${ES_TRANS_KEY}" ]]; then
    "${ES_BIN_DIR}/elasticsearch-certutil" cert --silent --pem \
      --in "${INST_TRANS}" \
      --out "${ES_CERT_DIR}/transport.zip" \
      --ca-cert "${ES_CA_CRT}" --ca-key "${ES_CA_KEY}"
    unzip -o "${ES_CERT_DIR}/transport.zip" -d "${ES_CERT_DIR}/transport" >/dev/null
    local FOUND_TRANS_CRT
    FOUND_TRANS_CRT="$(find "${ES_CERT_DIR}/transport" -type f -name '*.crt' | head -n1)"
    local FOUND_TRANS_KEY
    FOUND_TRANS_KEY="$(find "${ES_CERT_DIR}/transport" -type f -name '*.key' | head -n1)"
    cp -f "${FOUND_TRANS_CRT}" "${ES_TRANS_CRT}"
    cp -f "${FOUND_TRANS_KEY}" "${ES_TRANS_KEY}"
    chmod 0640 "${ES_TRANS_KEY}"
    chown root:elasticsearch "${ES_TRANS_KEY}" "${ES_TRANS_CRT}"
  else
    msg "Transport sertifikası zaten mevcut, atlanıyor."
  fi

  # Logstash için CA'nın bir kopyası
  cp -f "${ES_CA_CRT}" "${LOGSTASH_ES_CA}"
  chmod 0644 "${LOGSTASH_ES_CA}"

  msg "Sertifikalar hazır."
}

# ---- Konfig dosyalarını kopyala (repo -> /etc/...) ---------------------------
deploy_configs() {
  msg "Konfigürasyon dosyaları kopyalanıyor (files/ -> /etc/)..."

  # Elasticsearch
  install -d -m 0750 "${ES_CONF_DIR}"
  cp -f "${FILES_DIR}/elasticsearch/elasticsearch.yml" "${ES_CONF_DIR}/elasticsearch.yml"
  chown root:elasticsearch "${ES_CONF_DIR}/elasticsearch.yml"
  chmod 0640 "${ES_CONF_DIR}/elasticsearch.yml"

  # Kibana
  install -d -m 0755 /etc/kibana
  cp -f "${FILES_DIR}/kibana/kibana.yml" "/etc/kibana/kibana.yml"
  chmod 0644 "/etc/kibana/kibana.yml"

  # Logstash Pipeline
  install -d -m 0755 /etc/logstash/conf.d
  cp -f "${FILES_DIR}/logstash/fortigate.conf" "/etc/logstash/conf.d/fortigate.conf"
  chmod 0644 "/etc/logstash/conf.d/fortigate.conf"

  msg "Konfig kopyalama tamam."
}

# ---- Servisleri başlat + ES sağlık kontrolü ----------------------------------
start_services_and_wait_es() {
  msg "Servisler enable + start ediliyor..."
  systemctl daemon-reload
  systemctl enable --now "${ES_SERVICE}"
  systemctl enable --now "${KIBANA_SERVICE}"
  systemctl enable --now "${LOGSTASH_SERVICE}"

  msg "Elasticsearch sağlığını bekliyorum (TLS ile localhost)..."
  local RETRIES=60
  local OK=0
  for ((i=1; i<=RETRIES; i++)); do
    if curl -s --cacert "${ES_CA_CRT}" https://localhost:9200 >/dev/null 2>&1; then
      OK=1; break
    fi
    sleep 2
  done
  if [[ "${OK}" -ne 1 ]]; then
    err "Elasticsearch zamanında ayağa kalkmadı. Günlükleri kontrol edin: journalctl -u elasticsearch"
    exit 1
  fi
  msg "Elasticsearch erişilebilir."
}

# ---- elastic parolası reset + logstash rol/kullanıcı + keystore --------------
secure_and_create_identities() {
  msg "elastic parolası sıfırlanıyor (batch)..."
  # Komut çıktısından yeni parolayı yakala (son sözcük)
  local RAW_OUT
  RAW_OUT="$("${ES_BIN_DIR}/elasticsearch-reset-password" -u elastic -s -b 2>/dev/null || true)"
  if [[ -z "${RAW_OUT}" ]]; then
    err "elastic parolası alınamadı. ES TLS/sertifika veya enrollment ayarlarını kontrol edin."
    exit 1
  fi
  ELASTIC_PW="$(echo "${RAW_OUT}" | awk '{print $NF}' | tail -n1)"
  if [[ -z "${ELASTIC_PW}" ]]; then
    err "elastic parolası parse edilemedi."
    exit 1
  fi
  msg "elastic parolası üretildi."

  # Logstash için özel rol + kullanıcı
  msg "Logstash için rol ve kullanıcı oluşturuluyor (logstash_writer / logstash_ingest)..."
  local LOGSTASH_PW
  LOGSTASH_PW="$(openssl rand -base64 24 | tr -d '\n' | cut -c1-24)"

  # Rol: fortigate-logs-* üzerine yazma/oluşturma yetkileri + cluster monitor
  curl -s --fail --cacert "${ES_CA_CRT}" -u "elastic:${ELASTIC_PW}" \
    -H 'Content-Type: application/json' -X PUT \
    "https://localhost:9200/_security/role/logstash_writer" \
    -d '{
      "cluster": ["monitor"],
      "indices": [{
        "names": ["fortigate-logs-*"],
        "privileges": ["create_index","write","create","create_doc","view_index_metadata"]
      }]
    }' >/dev/null || warn "logstash_writer rolü oluşturulamadı (zaten var olabilir)."

  # Kullanıcı: logstash_ingest
  curl -s --fail --cacert "${ES_CA_CRT}" -u "elastic:${ELASTIC_PW}" \
    -H 'Content-Type: application/json' -X POST \
    "https://localhost:9200/_security/user/logstash_ingest" \
    -d "{\"password\":\"${LOGSTASH_PW}\",\"roles\":[\"logstash_writer\"]}" >/dev/null || \
    warn "logstash_ingest kullanıcısı oluşturulamadı (zaten var olabilir)."

  # Logstash keystore (parolayı düz metin yerine keystore'a)
  msg "Logstash keystore oluşturuluyor ve parola ekleniyor..."
  /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash create 2>/dev/null || true
  # --stdin ile keystore'a yaz
  (echo "${LOGSTASH_PW}") | /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash add --force ES_PW >/dev/null
  chown logstash:logstash "${LOGSTASH_KEYSTORE}" 2>/dev/null || true

  # Logstash'i yeniden başlat (keystore okunsun)
  systemctl restart "${LOGSTASH_SERVICE}"

  # Kibana enrollment token
  msg "Kibana enrollment token alınıyor..."
  ENROLL_TOKEN="$("${ES_BIN_DIR}/elasticsearch-create-enrollment-token" -s kibana 2>/dev/null || true)"
  if [[ -z "${ENROLL_TOKEN}" ]]; then
    warn "Enrollment token alınamadı (ES health veya TLS sorunu olabilir)."
  else
    msg "Enrollment token hazır."
  fi

  # Bilgileri ekrana yaz
  SERVER_IP="$(hostname -I | awk '{print $1}')"
  echo
  echo "==================== KURULUM ÖZETİ ===================="
  echo "Kibana URL            : http://${SERVER_IP}:${KIBANA_PORT}"
  echo "Elasticsearch (local) : https://localhost:9200"
  echo "Elastic kullanıcı     : elastic"
  echo "Elastic parola        : ${ELASTIC_PW}"
  if [[ -n "${ENROLL_TOKEN:-}" ]]; then
    echo "Kibana Enrollment Token:"
    echo "${ENROLL_TOKEN}"
  fi
  echo
  echo "Logstash kullanıcı     : logstash_ingest"
  echo "Logstash parola        : (Logstash keystore'da: ES_PW)"
  echo "Logstash Beats port    : ${LOGSTASH_BEATS_PORT}/tcp (dışa açık)"
  echo "CA (LS için)           : ${LOGSTASH_ES_CA}"
  echo "========================================================"
}

# ---- UFW varsa gerekli portları aç (opsiyonel) --------------------------------
maybe_open_firewall() {
  if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q "Status: active"; then
      msg "UFW etkin; 5601 ve 5044 portları izinleniyor..."
      ufw allow "${KIBANA_PORT}/tcp" || true
      ufw allow "${LOGSTASH_BEATS_PORT}/tcp" || true
    fi
  fi
}

# ------------------------------------------------------------------------------
main() {
  require_root
  msg "ELK Jammy otomatik kurulum başlıyor..."

  setup_repo_and_prereqs
  tune_sysctl
  install_packages
  prepare_dirs
  systemd_dropin_es
  generate_certs
  deploy_configs
  start_services_and_wait_es
  secure_and_create_identities
  maybe_open_firewall

  msg "Kurulum başarıyla tamamlandı."
}

main "$@"