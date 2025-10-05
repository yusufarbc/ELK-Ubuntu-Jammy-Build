#!/usr/bin/env bash
# =============================================================================
#  Elastic Stack (Elasticsearch, Kibana, Logstash) Otomatik Kurulum - Jammy
#  Hedef: Agentless toplama (WEF, Syslog, Kaspersky) + ECS & ILM + Data Streams
#  Tasarım:
#    - Elasticsearch: single-node, TLS etkin, YALNIZ localhost:9200 (SAN=localhost/127.0.0.1/::1)
#    - Kibana: 0.0.0.0:5601 (UI dışa açık, enrollment token ile bootstrap)
#    - Logstash: FortiGate:5044 (beats), WEF:5045 (beats), Syslog:5514 (TCP/UDP), Kaspersky:5516 (TCP/UDP)
#    - Logstash → Elasticsearch: data_stream => true (logs-<dataset>-default)
#    - ILM: logs-30d (hot→rollover; 30 gün sonunda delete), index template: logs-*-* (data_stream)
#    - Agent yok; WEF için yalnızca WEC sunucusuna Winlogbeat (tek ajan) tercih edilir.
# =============================================================================
set -Eeuo pipefail

# ---------- SÜRÜM & YOLLAR ----------
ES_VER="8.x"
ARCH="$(dpkg --print-architecture)"
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

ES_BIN="/usr/share/elasticsearch/bin"
ES_SERVICE="elasticsearch"
KIBANA_SERVICE="kibana"
LOGSTASH_SERVICE="logstash"

KIBANA_PORT=5601
LS_PORT_FGT=5044
LS_PORT_WEF=5045
LS_PORT_SYSLOG=5514     # syslog input (TCP+UDP aynı port)
LS_PORT_KASP=5516       # kaspersky (TCP+UDP aynı port)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILES_DIR="${REPO_ROOT}/files"

LOGSTASH_KEYSTORE="/etc/logstash/logstash.keystore"
LOGSTASH_CERT_DIR="/etc/logstash/certs"
LOGSTASH_ES_CA="${LOGSTASH_CERT_DIR}/ca.crt"

# ---------- YARDIMCI ----------
msg(){ echo -e "\e[1;32m[+]\e[0m $*"; }
warn(){ echo -e "\e[1;33m[!]\e[0m $*"; }
err(){ echo -e "\e[1;31m[-]\e[0m $*"; }
trap 'err "Bir hata oluştu (satır: $LINENO). Günlükleri kontrol edin."' ERR

require_root(){
  [[ $EUID -ne 0 ]] && { err "Bu betiği root olarak çalıştırın (sudo)."; exit 1; }
}

# ---------- REPO & BAĞIMLILIKLAR ----------
setup_repo(){
  msg "APT bağımlılıkları ve Elastic deposu hazırlanıyor..."
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y apt-transport-https ca-certificates curl wget jq unzip gpg lsb-release coreutils

  install -d -m 0755 "${KEYRING_DIR}"
  if [[ ! -f "${ELASTIC_KEY}" ]]; then
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o "${ELASTIC_KEY}"
    chmod 0644 "${ELASTIC_KEY}"
  fi

  # Eski duplike satırları temizle (ihtiyaten)
  sed -i '/artifacts.elastic.co/d' /etc/apt/sources.list || true
  find /etc/apt/sources.list.d -type f -name '*.list' -exec sed -i '/artifacts.elastic.co\/packages\/8.x\/apt/d' {} \; || true

  echo "deb [signed-by=${ELASTIC_KEY} arch=${ARCH}] https://artifacts.elastic.co/packages/${ES_VER}/apt stable main" > "${APT_LIST}"
  chmod 0644 "${APT_LIST}"
  apt-get update -y
  msg "APT deposu hazır."
}

# ---------- SİSTEM AYARI ----------
tune_sys(){
  msg "vm.max_map_count ayarlanıyor..."
  echo "vm.max_map_count=262144" > /etc/sysctl.d/99-elastic.conf
  sysctl -p /etc/sysctl.d/99-elastic.conf >/dev/null
}

# ---------- PAKET KURULUMU ----------
install_stack(){
  msg "Elasticsearch, Kibana, Logstash kuruluyor..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y elasticsearch kibana logstash
}

# ---------- DİZİNLER ----------
prepare_dirs(){
  msg "Dizin ve izinler..."
  install -d -m 0750 "${ES_CERT_DIR}" && chown root:elasticsearch "${ES_CERT_DIR}"
  install -d -m 0755 "${LOGSTASH_CERT_DIR}"
  install -d -m 0750 "${ES_LOG_DIR}" "${ES_DATA_DIR}" || true
  chown -R elasticsearch:elasticsearch "${ES_LOG_DIR}" "${ES_DATA_DIR}" || true
}

# ---------- systemd drop-in ----------
systemd_dropin(){
  msg "systemd drop-in (ES_PATH_CONF/ES_LOG_DIR)..."
  install -d -m 0755 /etc/systemd/system/elasticsearch.service.d
  cat > /etc/systemd/system/elasticsearch.service.d/override.conf <<EOF
[Service]
Environment="ES_PATH_CONF=${ES_CONF_DIR}"
Environment="ES_LOG_DIR=${ES_LOG_DIR}"
EOF
  systemctl daemon-reload
}

# ---------- SERTİFİKALAR (yalnız localhost) ----------
generate_certs(){
  msg "TLS sertifikaları (CA + HTTP + Transport) üretiliyor; SAN = localhost/127.0.0.1/::1 ..."
  # CA
  if [[ ! -f "${ES_CA_CRT}" || ! -f "${ES_CA_KEY}" ]]; then
    "${ES_BIN}/elasticsearch-certutil" ca --silent --pem --out "${ES_CERT_DIR}/ca.zip"
    unzip -o "${ES_CERT_DIR}/ca.zip" -d "${ES_CERT_DIR}/ca" >/dev/null
    local CA_CRT=$(find "${ES_CERT_DIR}/ca" -name '*.crt' | head -n1)
    local CA_KEY=$(find "${ES_CERT_DIR}/ca" -name '*.key' | head -n1)
    cp -f "${CA_CRT}" "${ES_CA_CRT}"
    cp -f "${CA_KEY}" "${ES_CA_KEY}"
    chmod 0644 "${ES_CA_CRT}"
    chmod 0640 "${ES_CA_KEY}"
    chown root:elasticsearch "${ES_CA_CRT}" "${ES_CA_KEY}"
  fi

  # instances.yml (http/transport)
  cat > "${ES_CERT_DIR}/instances_http.yml" <<'YAML'
instances:
  - name: es-http
    dns: ["localhost"]
    ip: ["127.0.0.1", "::1"]
YAML
  cat > "${ES_CERT_DIR}/instances_transport.yml" <<'YAML'
instances:
  - name: localhost
    dns: ["localhost"]
    ip: ["127.0.0.1", "::1"]
YAML

  # HTTP
  if [[ ! -f "${ES_HTTP_CRT}" || ! -f "${ES_HTTP_KEY}" ]]; then
    "${ES_BIN}/elasticsearch-certutil" cert --silent --pem \
      --in "${ES_CERT_DIR}/instances_http.yml" \
      --out "${ES_CERT_DIR}/http.zip" \
      --ca-cert "${ES_CA_CRT}" --ca-key "${ES_CA_KEY}"
    unzip -o "${ES_CERT_DIR}/http.zip" -d "${ES_CERT_DIR}/http" >/dev/null
    local HCRT=$(find "${ES_CERT_DIR}/http" -name '*.crt' | head -n1)
    local HKEY=$(find "${ES_CERT_DIR}/http" -name '*.key' | head -n1)
    cp -f "${HCRT}" "${ES_HTTP_CRT}"
    cp -f "${HKEY}" "${ES_HTTP_KEY}"
    chmod 0640 "${ES_HTTP_KEY}"
    chown root:elasticsearch "${ES_HTTP_CRT}" "${ES_HTTP_KEY}"
  fi

  # Transport
  if [[ ! -f "${ES_TRANS_CRT}" || ! -f "${ES_TRANS_KEY}" ]]; then
    "${ES_BIN}/elasticsearch-certutil" cert --silent --pem \
      --in "${ES_CERT_DIR}/instances_transport.yml" \
      --out "${ES_CERT_DIR}/transport.zip" \
      --ca-cert "${ES_CA_CRT}" --ca-key "${ES_CA_KEY}"
    unzip -o "${ES_CERT_DIR}/transport.zip" -d "${ES_CERT_DIR}/transport" >/dev/null
    local TCRT=$(find "${ES_CERT_DIR}/transport" -name '*.crt' | head -n1)
    local TKEY=$(find "${ES_CERT_DIR}/transport" -name '*.key' | head -n1)
    cp -f "${TCRT}" "${ES_TRANS_CRT}"
    cp -f "${TKEY}" "${ES_TRANS_KEY}"
    chmod 0640 "${ES_TRANS_KEY}"
    chown root:elasticsearch "${ES_TRANS_CRT}" "${ES_TRANS_KEY}"
  fi

  # Logstash için CA kopyası
  cp -f "${ES_CA_CRT}" "${LOGSTASH_ES_CA}"
  chmod 0644 "${LOGSTASH_ES_CA}"
}

# ---------- KONFİG DOSYALARI ----------
deploy_configs(){
  msg "Konfigürasyon dosyaları dağıtılıyor..."
  # ES
  install -d -m 0750 "${ES_CONF_DIR}"
  cp -f "${FILES_DIR}/elasticsearch/elasticsearch.yml" "${ES_CONF_DIR}/elasticsearch.yml"
  chown root:elasticsearch "${ES_CONF_DIR}/elasticsearch.yml"
  chmod 0640 "${ES_CONF_DIR}/elasticsearch.yml"
  # Kibana
  install -d -m 0755 /etc/kibana
  cp -f "${FILES_DIR}/kibana/kibana.yml" "/etc/kibana/kibana.yml"
  chmod 0644 "/etc/kibana/kibana.yml"
  # Logstash pipelines
  install -d -m 0755 /etc/logstash/conf.d
  cp -f "${FILES_DIR}/logstash/fortigate.conf"     "/etc/logstash/conf.d/fortigate.conf"
  cp -f "${FILES_DIR}/logstash/windows_wef.conf"   "/etc/logstash/conf.d/windows_wef.conf"
  cp -f "${FILES_DIR}/logstash/syslog.conf"        "/etc/logstash/conf.d/syslog.conf"
  cp -f "${FILES_DIR}/logstash/kaspersky.conf"     "/etc/logstash/conf.d/kaspersky.conf"
  chmod 0644 /etc/logstash/conf.d/*.conf
}

# ---------- SERVİSLER + ES HEALTH ----------
start_and_wait_es(){
  msg "Servisler enable+start..."
  systemctl daemon-reload
  systemctl enable --now "${ES_SERVICE}" "${KIBANA_SERVICE}" "${LOGSTASH_SERVICE}"

  msg "Elasticsearch sağlığını bekliyorum..."
  for i in {1..60}; do
    if curl -s --cacert "${ES_CA_CRT}" https://localhost:9200 >/dev/null 2>&1; then break; fi
    sleep 2
    [[ $i -eq 60 ]] && { err "Elasticsearch kalkmadı."; exit 1; }
  done
}

# ---------- KİMLİK + KEYSTORE + ENROLLMENT ----------
secure_identities(){
  msg "elastic parolası batch reset..."
  local RAW="$("${ES_BIN}/elasticsearch-reset-password" -u elastic -s -b 2>/dev/null || true)"
  ELASTIC_PW="$(echo "${RAW}" | awk '{print $NF}' | tail -n1)"
  [[ -z "${ELASTIC_PW}" ]] && { err "elastic parolası alınamadı."; exit 1; }

  msg "Logstash yetkileri (rol+kullanıcı) ve keystore..."
  local LS_PW; LS_PW="$(openssl rand -base64 24 | tr -d '\n' | cut -c1-24)"

  # Rol: data stream logs-*-default yazma
  curl -s --fail --cacert "${ES_CA_CRT}" -u "elastic:${ELASTIC_PW}" \
    -H 'Content-Type: application/json' -X PUT \
    https://localhost:9200/_security/role/logstash_writer \
    -d '{
      "cluster": ["monitor"],
      "indices": [{
        "names": ["logs-*-*"],
        "privileges": ["create_index","write","create","view_index_metadata"]
      }]
    }' >/dev/null || warn "rol (logstash_writer) zaten var olabilir."

  # Kullanıcı
  curl -s --fail --cacert "${ES_CA_CRT}" -u "elastic:${ELASTIC_PW}" \
    -H 'Content-Type: application/json' -X POST \
    https://localhost:9200/_security/user/logstash_ingest \
    -d "{\"password\":\"${LS_PW}\",\"roles\":[\"logstash_writer\"]}" >/dev/null || \
    warn "kullanıcı (logstash_ingest) zaten var olabilir."

  # Keystore’a parola
  /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash create 2>/dev/null || true
  (echo "${LS_PW}") | /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash add --force ES_PW >/dev/null
  chown logstash:logstash "${LOGSTASH_KEYSTORE}" 2>/dev/null || true
  systemctl restart "${LOGSTASH_SERVICE}"

  # Kibana enrollment token
  ENROLL_TOKEN="$("${ES_BIN}/elasticsearch-create-enrollment-token" -s kibana 2>/dev/null || true)"
  [[ -z "${ENROLL_TOKEN}" ]] && warn "Enrollment token alınamadı."
}

# ---------- ILM + TEMPLATE (data stream) ----------
setup_ilm_templates(){
  msg "ILM ve index template (data stream) oluşturuluyor..."
  # ILM: logs-30d (hot rollover + 30 günde delete)
  curl -s --fail --cacert "${ES_CA_CRT}" -u "elastic:${ELASTIC_PW}" \
    -H 'Content-Type: application/json' -X PUT \
    https://localhost:9200/_ilm/policy/logs-30d \
    -d '{
      "policy": {
        "phases": {
          "hot": {"actions": {"rollover": {"max_primary_shard_size":"25gb","max_age":"7d"}}},
          "delete": {"min_age":"30d","actions":{"delete":{}}}
        }
      }
    }' >/dev/null || warn "ILM policy oluşturulamadı (var olabilir)."

  # Data stream template: logs-*-*  → ILM: logs-30d
  curl -s --fail --cacert "${ES_CA_CRT}" -u "elastic:${ELASTIC_PW}" \
    -H 'Content-Type: application/json' -X PUT \
    https://localhost:9200/_index_template/logs-ds-template \
    -d '{
      "index_patterns": ["logs-*-*"],
      "data_stream": {},
      "template": {
        "settings": {
          "index.lifecycle.name": "logs-30d"
        }
      },
      "priority": 200
    }' >/dev/null || warn "index template oluşturulamadı (var olabilir)."
}

# ---------- UFW (varsa) ----------
maybe_open_firewall(){
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    msg "UFW açık: 5601, 5044, 5045, 5514, 5516 izinleniyor..."
    ufw allow "${KIBANA_PORT}/tcp" || true
    ufw allow "${LS_PORT_FGT}/tcp" || true
    ufw allow "${LS_PORT_WEF}/tcp" || true
    ufw allow "${LS_PORT_SYSLOG}/tcp" || true
    ufw allow "${LS_PORT_SYSLOG}/udp" || true
    ufw allow "${LS_PORT_KASP}/tcp" || true
    ufw allow "${LS_PORT_KASP}/udp" || true
  fi
}

# ---------- ÖZET ----------
print_summary(){
  local IP="$(hostname -I | awk '{print $1}')"
  echo
  echo "==================== KURULUM ÖZETİ ===================="
  echo "Kibana URL            : http://${IP}:${KIBANA_PORT}"
  echo "Elasticsearch         : https://localhost:9200  (yalnız localhost)"
  echo "Elastic kullanıcı     : elastic"
  echo "Elastic parola        : ${ELASTIC_PW}"
  [[ -n "${ENROLL_TOKEN:-}" ]] && { echo "Kibana Enrollment Token:"; echo "${ENROLL_TOKEN}"; }
  echo
  echo "Logstash kullanıcı    : logstash_ingest (parola keystore: ES_PW)"
  echo "FortiGate Beats       : ${LS_PORT_FGT}/tcp"
  echo "WEF (Winlogbeat→LS)   : ${LS_PORT_WEF}/tcp"
  echo "Syslog (RFC3164)      : ${LS_PORT_SYSLOG}/tcp+udp"
  echo "Kaspersky (syslog/JSON): ${LS_PORT_KASP}/tcp+udp"
  echo "Data Streams          : logs-<dataset>-default (ILM: logs-30d)"
  echo "CA (LS için)          : ${LOGSTASH_ES_CA}"
  echo "========================================================"
}

main(){
  require_root
  msg "Elastic Stack (agentless) kurulum başlıyor..."
  setup_repo
  tune_sys
  install_stack
  prepare_dirs
  systemd_dropin
  generate_certs
  deploy_configs
  start_and_wait_es
  secure_identities
  setup_ilm_templates
  maybe_open_firewall
  print_summary
  msg "Kurulum tamamlandı."
}
main "$@"