#!/usr/bin/env bash
# =============================================================================
# ELK-Ubuntu-Jammy-Build - Tek Komutla Agentless Elastic Stack Kurulumu
# -----------------------------------------------------------------------------
# Bu betik, Ubuntu 22.04 (Jammy) üzerinde aşağıdaki mimariyi idempotent şekilde
# kurar ve yapılandırır:
#   - Elasticsearch: TLS etkin, sadece localhost:9200 (single-node)
#   - Kibana: 0.0.0.0:5601 (dışa açık), ES CA’sına güvenir, enrollment destekli
#   - Logstash: dışa açık girişler (5044/5045/5514/5515/5516), ECS’e yakın filtreler
#   - Sertifikalar: Localhost SAN (localhost, 127.0.0.1, ::1)
#   - ILM: logs-90d (90 günde silme), data_stream + index template
#   - Güvenlik: logstash_ingest rol/kullanıcı, parola keystore’da (ES_PW)
#
# Tasarım Notları:
#   - ES HTTP katmanında **PKCS#12** keystore kullanılır (enrollment token için şart).
#   - ES transport için **PEM** kullanılır.
#   - Kibana CA doğrulaması açık; encryption key’ler ortam değişkeninden geçilir.
#   - Logstash keystore parolası otomatik üretilir ve /etc/default/logstash içine yazılır.
#
# Kullanım:
#   sudo ./elk_setup_ubuntu_jammy.sh
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

#------------------------------- Yardımcılar ----------------------------------#
STEP="başlangıç"
log(){ echo -e "→ ${1}"; }
ok(){  echo -e "[+] ${1}"; }
die(){
  echo "[-] Hata adımında düştü: '${STEP}'"
  echo "----- elasticsearch journal (son 50) -----"; journalctl -u elasticsearch -n 50 --no-pager || true
  echo "----- kibana journal (son 50) -----------"; journalctl -u kibana -n 50 --no-pager || true
  echo "----- logstash journal (son 50) ---------"; journalctl -u logstash -n 50 --no-pager || true
  exit 1
}
trap 'die' ERR

require_root(){
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Bu betik root hakları ile çalıştırılmalıdır."; exit 1
  fi
}

#------------------------------- Yol/Değişkenler ------------------------------#
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILES_DIR="${SCRIPT_DIR}/files"

ES_BIN="/usr/share/elasticsearch/bin"
ES_SVC="elasticsearch"
KB_SVC="kibana"
LS_SVC="logstash"

ES_CONF_DIR="/etc/elasticsearch"
ES_CERT_DIR="${ES_CONF_DIR}/certs"
ES_LOG_DIR="/var/log/elasticsearch"

LS_CONF_DIR="/etc/logstash"
LS_LOG_DIR="/var/log/logstash"

KB_DEFAULT="/etc/default/kibana"
LS_DEFAULT="/etc/default/logstash"

# Sertifika yolları
ES_CA_CRT="${ES_CERT_DIR}/ca.crt"
ES_CA_KEY="${ES_CERT_DIR}/ca.key"
ES_HTTP_P12="${ES_CERT_DIR}/http.p12"               # Enrollment token için PKCS12
ES_TRANS_CRT="${ES_CERT_DIR}/transport.crt"
ES_TRANS_KEY="${ES_CERT_DIR}/transport.key"

# Logstash tarafında ES CA
LOGSTASH_ES_CA="${LS_CONF_DIR}/certs/ca.crt"

#------------------------------- APT & Bağımlılıklar --------------------------#
prep_apt(){
  STEP="1/10 APT deposu ve bağımlılıklar"
  log "${STEP}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y lsb-release ca-certificates coreutils curl gpg wget apt-transport-https jq unzip

  install -d -m 0755 /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/elastic.gpg ]]; then
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch \
      | gpg --dearmor -o /etc/apt/keyrings/elastic.gpg
    ok "Elastic GPG anahtarı eklendi: /etc/apt/keyrings/elastic.gpg"
  fi

  local SRC="/etc/apt/sources.list.d/elastic-8.x.list"
  if [[ ! -f "${SRC}" ]]; then
    echo "deb [signed-by=/etc/apt/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" > "${SRC}"
  fi
  apt-get update -y
}

#------------------------------- Kernel Ayarları -------------------------------#
sysctl_tune(){
  STEP="2/10 vm.max_map_count ayarı"
  log "${STEP}"
  echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-elastic.conf
  sysctl --system >/dev/null
}

#------------------------------- Paket Kurulumu --------------------------------#
install_packages(){
  STEP="3/10 Elasticsearch, Kibana, Logstash kurulumu"
  log "${STEP}"
  apt-get install -y elasticsearch kibana logstash
}

#------------------------------- Dizin/İzinler --------------------------------#
prepare_dirs(){
  STEP="4/10 Dizin ve izinler"
  log "${STEP}"
  install -d -m 0755 "${ES_CONF_DIR}" "${ES_CERT_DIR}" "${ES_LOG_DIR}"
  install -d -m 0755 "${LS_CONF_DIR}" "${LS_LOG_DIR}" "${LS_CONF_DIR}/conf.d" "${LS_CONF_DIR}/certs"
  chown -R root:elasticsearch "${ES_CONF_DIR}" "${ES_LOG_DIR}" || true
  chown -R logstash:logstash "${LS_LOG_DIR}" || true
}

#------------------------------- systemd Drop-in -------------------------------#
systemd_dropin(){
  STEP="5/10 systemd drop-in (ES_PATH_CONF/ES_LOG_DIR)"
  log "${STEP}"
  install -d -m 0755 /etc/systemd/system/${ES_SVC}.service.d
  cat > /etc/systemd/system/${ES_SVC}.service.d/override.conf <<EOF
[Service]
Environment=ES_PATH_CONF=${ES_CONF_DIR}
Environment=ES_LOG_DIR=${ES_LOG_DIR}
EOF
  systemctl daemon-reload
}

#------------------------------- Sertifikalar ---------------------------------#
generate_certs(){
  STEP="6/10 TLS sertifikaları (CA + HTTP[PKCS12] + Transport[PEM]) — SAN=localhost/127.0.0.1/::1"
  log "${STEP}"

  # CA (PEM)
  if [[ ! -f "${ES_CA_CRT}" || ! -f "${ES_CA_KEY}" ]]; then
    "${ES_BIN}/elasticsearch-certutil" ca --silent --pem --out "${ES_CERT_DIR}/ca.zip"
    unzip -o "${ES_CERT_DIR}/ca.zip" -d "${ES_CERT_DIR}/ca" >/dev/null
    cp -f "$(find "${ES_CERT_DIR}/ca" -name '*.crt' | head -n1)" "${ES_CA_CRT}"
    cp -f "$(find "${ES_CERT_DIR}/ca" -name '*.key' | head -n1)" "${ES_CA_KEY}"
    chmod 0644 "${ES_CA_CRT}"
    chmod 0640 "${ES_CA_KEY}"
    chown root:elasticsearch "${ES_CA_CRT}" "${ES_CA_KEY}"
  fi

  # instances.yml
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

  # HTTP sertifikası: **PKCS12** (enrollment token için şart)
  if [[ ! -f "${ES_HTTP_P12}" ]]; then
    "${ES_BIN}/elasticsearch-certutil" cert --silent \
      --in "${ES_CERT_DIR}/instances_http.yml" \
      --out "${ES_HTTP_P12}" \
      --ca-cert "${ES_CA_CRT}" --ca-key "${ES_CA_KEY}"
    chmod 0640 "${ES_HTTP_P12}"
    chown root:elasticsearch "${ES_HTTP_P12}"
  fi

  # Transport sertifikası: PEM
  if [[ ! -f "${ES_TRANS_CRT}" || ! -f "${ES_TRANS_KEY}" ]]; then
    "${ES_BIN}/elasticsearch-certutil" cert --silent --pem \
      --in "${ES_CERT_DIR}/instances_transport.yml" \
      --out "${ES_CERT_DIR}/transport.zip" \
      --ca-cert "${ES_CA_CRT}" --ca-key "${ES_CA_KEY}"
    unzip -o "${ES_CERT_DIR}/transport.zip" -d "${ES_CERT_DIR}/transport" >/dev/null
    cp -f "$(find "${ES_CERT_DIR}/transport" -name '*.crt' | head -n1)" "${ES_TRANS_CRT}"
    cp -f "$(find "${ES_CERT_DIR}/transport" -name '*.key' | head -n1)" "${ES_TRANS_KEY}"
    chmod 0640 "${ES_TRANS_KEY}"
    chown root:elasticsearch "${ES_TRANS_CRT}" "${ES_TRANS_KEY}"
  fi

  # Logstash için CA kopyası
  cp -f "${ES_CA_CRT}" "${LOGSTASH_ES_CA}"
  chmod 0644 "${LOGSTASH_ES_CA}"
}

#------------------------------- Konfig Kopyalama ------------------------------#
deploy_configs(){
  STEP="7/10 Konfigürasyon dosyaları"
  log "${STEP}"

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

#------------------------------- Servis Başlat --------------------------------#
start_services(){
  STEP="8/10 Servisleri enable & start"
  log "${STEP}"
  systemctl enable "${ES_SVC}" "${KB_SVC}" "${LS_SVC}"

  systemctl start "${ES_SVC}"

  # ES hazır olana kadar bekle
  STEP="8/10 Elasticsearch hazır bekleyiş"
  for i in {1..60}; do
    if curl -fsS --cacert "${ES_CA_CRT}" https://localhost:9200 >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done

  systemctl start "${KB_SVC}"
  systemctl start "${LS_SVC}"
}

#------------------------------- ES Şifre/Rol/Keystore ------------------------#
provision_security(){
  STEP="9/10 elastic parolasını reset + Logstash rol/kullanıcı + keystore"
  log "${STEP}"

  # elastic parolasını batch reset
  ELASTIC_PW="$("${ES_BIN}/elasticsearch-reset-password" -u elastic -b)"
  : "${ELASTIC_PW:?elastic parola alınamadı}"

  # logstash_ingest rolü
  curl -sS --cacert "${ES_CA_CRT}" -u "elastic:${ELASTIC_PW}" \
    -X PUT "https://localhost:9200/_security/role/logstash_ingest" \
    -H 'Content-Type: application/json' -d @- <<'JSON' >/dev/null
{
  "cluster": ["monitor"],
  "indices": [
    {
      "names": [ "logs-*-*" ],
      "privileges": ["auto_configure","create_doc","create","write","index","read","view_index_metadata"]
    }
  ],
  "run_as": []
}
JSON

  # logstash_ingest kullanıcısı (rasgele parola)
  LOGSTASH_PW="$(openssl rand -base64 24 | tr -d '\n' | head -c 32)"
  curl -sS --cacert "${ES_CA_CRT}" -u "elastic:${ELASTIC_PW}" \
    -X PUT "https://localhost:9200/_security/user/logstash_ingest" \
    -H 'Content-Type: application/json' -d @- <<JSON >/dev/null
{
  "password": "${LOGSTASH_PW}",
  "roles": [ "logstash_ingest" ],
  "full_name": "Logstash Ingest"
}
JSON

  # Logstash keystore parolası (kalıcı)
  LSKS_PASS="$(openssl rand -base64 24 | tr -d '\n' | head -c 32)"
  install -m 0644 /dev/null "${LS_DEFAULT}" || true
  if ! grep -q '^LOGSTASH_KEYSTORE_PASS=' "${LS_DEFAULT}" 2>/dev/null; then
    echo "LOGSTASH_KEYSTORE_PASS=${LSKS_PASS}" >> "${LS_DEFAULT}"
  else
    sed -i "s|^LOGSTASH_KEYSTORE_PASS=.*|LOGSTASH_KEYSTORE_PASS=${LSKS_PASS}|" "${LS_DEFAULT}"
  fi

  # Keystore oluştur + ES_PW ekle (prompt yok)
  LOGSTASH_KEYSTORE_PASS="${LSKS_PASS}" /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash create --force
  printf "%s" "${LOGSTASH_PW}" | LOGSTASH_KEYSTORE_PASS="${LSKS_PASS}" /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash add ES_PW --stdin --force

  systemctl restart "${LS_SVC}"
}

#------------------------------- Kibana Enrollment + Key’ler ------------------#
kibana_enroll(){
  STEP="9/10 Kibana enrollment + encryption keys"
  log "${STEP}"

  # Kibana encryption keys → /etc/default/kibana
  if ! grep -q 'KBN_SECURITY_KEY' "${KB_DEFAULT}" 2>/dev/null; then
    read -r K1 K2 K3 < <(/usr/share/kibana/bin/kibana-encryption-keys generate -q \
      | awk -F': ' '/security/{print $2} /encryptedSavedObjects/{print $2} /reporting/{print $2}')
    {
      echo "KBN_SECURITY_KEY=${K1}"
      echo "KBN_SAVEDOBJ_KEY=${K2}"
      echo "KBN_REPORTING_KEY=${K3}"
    } >> "${KB_DEFAULT}"
  fi

  # Enrollment token üret (HTTP keystore PKCS12 olduğundan sorunsuz)
  KBN_TOKEN="$("${ES_BIN}/elasticsearch-create-enrollment-token" -s kibana || true)"

  # Headless enrollment (başarısız olsa bile token’ı yazdıracağız)
  if [[ -n "${KBN_TOKEN}" ]]; then
    /usr/share/kibana/bin/kibana-setup --enrollment-token "${KBN_TOKEN}" || true
  fi

  systemctl restart "${KB_SVC}"

  # Özet değişkenleri dışarı aktar (print_summary için)
  export __ELASTIC_PW="${ELASTIC_PW}"
  export __KBN_TOKEN="${KBN_TOKEN:-}"
}

#------------------------------- ILM + Template -------------------------------#
ilm_and_templates(){
  STEP="10/10 ILM (logs-90d) + index template (logs-*-*)"
  log "${STEP}"

  curl -sS --cacert "${ES_CA_CRT}" -u "elastic:${ELASTIC_PW}" \
    -X PUT "https://localhost:9200/_ilm/policy/logs-90d" \
    -H 'Content-Type: application/json' -d @- <<'JSON' >/dev/null
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": { "max_primary_shard_size": "25gb", "max_age": "7d" }
        }
      },
      "delete": { "min_age": "90d", "actions": { "delete": {} } }
    }
  }
}
JSON

  curl -sS --cacert "${ES_CA_CRT}" -u "elastic:${ELASTIC_PW}" \
    -X PUT "https://localhost:9200/_index_template/logs-ds-template" \
    -H 'Content-Type: application/json' -d @- <<'JSON' >/dev/null
{
  "index_patterns": ["logs-*-*"],
  "data_stream": {},
  "template": {
    "settings": {
      "index.lifecycle.name": "logs-90d",
      "index.number_of_shards": 1,
      "index.number_of_replicas": 0
    }
  },
  "priority": 500
}
JSON
}

#------------------------------- UFW (opsiyonel) ------------------------------#
ufw_allow(){
  # UFW aktifse, gerekli portları aç
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    log "UFW kural kontrolü (varsa)"
    ufw allow 5601/tcp || true
    ufw allow 5044/tcp || true
    ufw allow 5045/tcp || true
    ufw allow 5514/tcp || true
    ufw allow 5514/udp || true
    ufw allow 5515/tcp || true
    ufw allow 5516/tcp || true
    ufw allow 5516/udp || true
  fi
}

#------------------------------- Özet -----------------------------------------#
print_summary(){
  echo
  echo "==================== KURULUM ÖZETİ ===================="
  echo "Kibana URL            : http://<Sunucu_IP_veya_FQDN>:5601"
  echo "Elasticsearch         : https://localhost:9200  (yalnız localhost)"
  echo "Elastic kullanıcı     : elastic"
  echo "Elastic parola        : ${__ELASTIC_PW}"
  if [[ -n "${__KBN_TOKEN:-}" ]]; then
    echo "Kibana Enrollment Tok.: ${__KBN_TOKEN}"
  else
    echo "Kibana Enrollment Tok.: (Gerekirse) sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana"
  fi
  echo
  echo "Logstash kullanıcı    : logstash_ingest (parola keystore: ES_PW)"
  echo "FortiGate Beats       : 5044/tcp"
  echo "WEF (Winlogbeat→LS)   : 5045/tcp"
  echo "Syslog (RFC3164)      : 5514/tcp+udp"
  echo "Syslog (RFC5424)      : 5515/tcp"
  echo "Kaspersky             : 5516/tcp+udp"
  echo "Data Streams          : logs-<dataset>-default (ILM: logs-90d)"
  echo "CA (LS için)          : ${LOGSTASH_ES_CA}"
  echo "========================================================"
  ok "Kurulum tamamlandı."
}

#--------------------------------- Ana Akış -----------------------------------#
require_root
ok "Elastic Stack (agentless) kurulum başlıyor..."
prep_apt
sysctl_tune
install_packages
prepare_dirs
systemd_dropin
generate_certs
deploy_configs
start_services
provision_security
kibana_enroll
ilm_and_templates
ufw_allow
print_summary