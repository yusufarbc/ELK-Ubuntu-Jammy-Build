#!/usr/bin/env bash
# =============================================================================
# Elastic Stack (Elasticsearch, Kibana, Logstash) Otomatik Kurulum - Ubuntu 22.04 (Jammy)
# Tasarım: ES yalnız localhost:9200 (TLS), Kibana/Logstash dışa açık, agentless toplama
# =============================================================================

# ---- Yardımcı çıktı ----
msg(){ echo -e "\e[1;32m[+]\e[0m $*"; }
warn(){ echo -e "\e[1;33m[!]\e[0m $*"; }
err(){ echo -e "\e[1;31m[-]\e[0m $*"; }
step(){ CURRENT_STEP="$*"; echo -e "\e[1;36m→ ${CURRENT_STEP}\e[0m"; }

# ---- Küresel değişken iskeleti (değerler init_env içinde atanır) ----
CURRENT_STEP="başlangıç"
ES_VER="8.x"
ARCH=""
APT_LIST=""
KEYRING_DIR="/etc/apt/keyrings"
ELASTIC_KEY="${KEYRING_DIR}/elastic.gpg"

ES_CONF_DIR="/etc/elasticsearch"
ES_DATA_DIR="/var/lib/elasticsearch"
ES_LOG_DIR="/var/log/elasticsearch"
ES_CERT_DIR="${ES_CONF_DIR}/certs"
ES_BIN="/usr/share/elasticsearch/bin"

ES_CA_CRT="${ES_CERT_DIR}/ca.crt"
ES_CA_KEY="${ES_CERT_DIR}/ca.key"
ES_HTTP_CRT="${ES_CERT_DIR}/http.crt"
ES_HTTP_KEY="${ES_CERT_DIR}/http.key"
ES_TRANS_CRT="${ES_CERT_DIR}/transport.crt"
ES_TRANS_KEY="${ES_CERT_DIR}/transport.key"

ES_SERVICE="elasticsearch"
KIBANA_SERVICE="kibana"
LOGSTASH_SERVICE="logstash"

KIBANA_PORT=5601
LS_PORT_FGT=5044
LS_PORT_WEF=5045
LS_PORT_SYSLOG=5514
LS_PORT_RFC5424=5515
LS_PORT_KASP=5516

REPO_ROOT=""
FILES_DIR=""
LOGSTASH_KEYSTORE="/etc/logstash/logstash.keystore"
LOGSTASH_CERT_DIR="/etc/logstash/certs"
LOGSTASH_ES_CA="${LOGSTASH_CERT_DIR}/ca.crt"

ELASTIC_PW=""
ENROLL_TOKEN=""

# ---- Hata yakalayıcı (main içinde etkinleştirilecek) ----
on_error(){
  local ec=$?
  err "Hata adımında düştü: '${CURRENT_STEP}'"
  if command -v journalctl >/dev/null 2>&1; then
    echo "----- elasticsearch journal (son 50) -----"; journalctl -u elasticsearch -n 50 --no-pager || true
    echo "----- kibana journal (son 50) -----------"; journalctl -u kibana -n 50 --no-pager || true
    echo "----- logstash journal (son 50) ---------"; journalctl -u logstash -n 50 --no-pager || true
  fi
  exit "${ec}"
}

require_root(){ [[ $EUID -ne 0 ]] && { err "Bu betiği root olarak çalıştırın (sudo)."; exit 1; }; }

init_env(){
  step "0/10 Ortam hazırlanıyor"
  # Bash güvenli modlar (buraya kadar erken hata yok)
  set -eE -o pipefail
  trap on_error ERR

  # DEBUG=1 ile ayrıntılı izleme
  [[ "${DEBUG:-0}" == "1" ]] && set -x

  # Mimari & repo yolu güvenli hesaplama
  ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
  APT_LIST="/etc/apt/sources.list.d/elastic-${ES_VER}.list"

  # Betik dizini (sudo ile de doğru bulur)
  REPO_ROOT="$(cd "$(dirname "$0")" && pwd -P)"
  FILES_DIR="${REPO_ROOT}/files"

  # İkili dosyalar yerinde mi?
  command -v curl >/dev/null 2>&1 || apt-get update -y
}

setup_repo(){
  step "1/10 APT deposu ve bağımlılıklar"
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y apt-transport-https ca-certificates curl wget jq unzip gpg lsb-release coreutils

  install -d -m 0755 "${KEYRING_DIR}"
  if [[ ! -f "${ELASTIC_KEY}" ]]; then
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o "${ELASTIC_KEY}"
    chmod 0644 "${ELASTIC_KEY}"
  fi
  # Duplike satırları temizle
  sed -i '/artifacts.elastic.co/d' /etc/apt/sources.list || true
  find /etc/apt/sources.list.d -type f -name '*.list' -exec sed -i '/artifacts.elastic.co\/packages\/8.x\/apt/d' {} \; || true

  echo "deb [signed-by=${ELASTIC_KEY} arch=${ARCH}] https://artifacts.elastic.co/packages/${ES_VER}/apt stable main" > "${APT_LIST}"
  chmod 0644 "${APT_LIST}"
  apt-get update -y
}

tune_sys(){
  step "2/10 vm.max_map_count ayarı"
  echo "vm.max_map_count=262144" > /etc/sysctl.d/99-elastic.conf
  sysctl -p /etc/sysctl.d/99-elastic.conf >/dev/null
}

install_stack(){
  step "3/10 Elasticsearch, Kibana, Logstash kurulumu"
  DEBIAN_FRONTEND=noninteractive apt-get install -y elasticsearch kibana logstash
}

prepare_dirs(){
  step "4/10 Dizin ve izinler"
  install -d -m 0750 "${ES_CERT_DIR}" && chown root:elasticsearch "${ES_CERT_DIR}"
  install -d -m 0755 "${LOGSTASH_CERT_DIR}"
  install -d -m 0750 "${ES_LOG_DIR}" "${ES_DATA_DIR}" || true
  chown -R elasticsearch:elasticsearch "${ES_LOG_DIR}" "${ES_DATA_DIR}" || true
}

systemd_dropin(){
  step "5/10 systemd drop-in (ES_PATH_CONF/ES_LOG_DIR)"
  install -d -m 0755 /etc/systemd/system/elasticsearch.service.d
  cat > /etc/systemd/system/elasticsearch.service.d/override.conf <<EOF
[Service]
Environment="ES_PATH_CONF=${ES_CONF_DIR}"
Environment="ES_LOG_DIR=${ES_LOG_DIR}"
EOF
  systemctl daemon-reload
}

generate_certs(){
  step "6/10 TLS sertifikaları (CA+HTTP+Transport) — SAN=localhost/127.0.0.1/::1"

  # --- CA üret ---
  if [[ ! -f "${ES_CA_CRT}" || ! -f "${ES_CA_KEY}" ]]; then
    "${ES_BIN}/elasticsearch-certutil" ca --silent --pem --out "${ES_CERT_DIR}/ca.zip"
    unzip -o "${ES_CERT_DIR}/ca.zip" -d "${ES_CERT_DIR}/ca" >/dev/null
    local CA_CRT; CA_CRT="$(find "${ES_CERT_DIR}/ca" -name '*.crt' | head -n1)"
    local CA_KEY; CA_KEY="$(find "${ES_CERT_DIR}/ca" -name '*.key' | head -n1)"
    cp -f "${CA_CRT}" "${ES_CA_CRT}"
    cp -f "${CA_KEY}" "${ES_CA_KEY}"
    chmod 0644 "${ES_CA_CRT}"
    chmod 0640 "${ES_CA_KEY}"
    chown root:elasticsearch "${ES_CA_CRT}" "${ES_CA_KEY}"
  fi

  # --- instances.yml (yalnız localhost) ---
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

  # --- HTTP sertifikası (PEM) ---
  if [[ ! -f "${ES_HTTP_CRT}" || ! -f "${ES_HTTP_KEY}" ]]; then
    "${ES_BIN}/elasticsearch-certutil" cert --silent --pem \
      --in "${ES_CERT_DIR}/instances_http.yml" \
      --out "${ES_CERT_DIR}/http.zip" \
      --ca-cert "${ES_CA_CRT}" --ca-key "${ES_CA_KEY}"
    unzip -o "${ES_CERT_DIR}/http.zip" -d "${ES_CERT_DIR}/http" >/dev/null
    local HCRT; HCRT="$(find "${ES_CERT_DIR}/http" -name '*.crt' | head -n1)"
    local HKEY; HKEY="$(find "${ES_CERT_DIR}/http" -name '*.key' | head -n1)"
    cp -f "${HCRT}" "${ES_HTTP_CRT}"
    cp -f "${HKEY}" "${ES_HTTP_KEY}"
    chmod 0640 "${ES_HTTP_KEY}"
    chown root:elasticsearch "${ES_HTTP_CRT}" "${ES_HTTP_KEY}"
  fi

  # --- Transport sertifikası (PEM) ---
  if [[ ! -f "${ES_TRANS_CRT}" || ! -f "${ES_TRANS_KEY}" ]]; then
    "${ES_BIN}/elasticsearch-certutil" cert --silent --pem \
      --in "${ES_CERT_DIR}/instances_transport.yml" \
      --out "${ES_CERT_DIR}/transport.zip" \
      --ca-cert "${ES_CA_CRT}" --ca-key "${ES_CA_KEY}"
    unzip -o "${ES_CERT_DIR}/transport.zip" -d "${ES_CERT_DIR}/transport" >/dev/null
    local TCRT; TCRT="$(find "${ES_CERT_DIR}/transport" -name '*.crt' | head -n1)"
    local TKEY; TKEY="$(find "${ES_CERT_DIR}/transport" -name '*.key' | head -n1)"
    cp -f "${TCRT}" "${ES_TRANS_CRT}"
    cp -f "${TKEY}" "${ES_TRANS_KEY}"
    chmod 0640 "${ES_TRANS_KEY}"
    chown root:elasticsearch "${ES_TRANS_CRT}" "${ES_TRANS_KEY}"
  fi

  # --- Logstash için CA kopyası ---
  cp -f "${ES_CA_CRT}" "${LOGSTASH_ES_CA}"
  chmod 0644 "${LOGSTASH_ES_CA}"

  # --- Kibana için CA kopyası (izin duvarına takılmasın) ---
  install -d -m 0755 /etc/kibana/certs
  cp -f "${ES_CA_CRT}" /etc/kibana/certs/ca.crt
  chmod 0644 /etc/kibana/certs/ca.crt
  chown root:root /etc/kibana/certs/ca.crt

  # --- HTTP için PKCS#12 keystore (enrollment token aracı bunu ister) ---
  if [[ ! -f "${ES_CERT_DIR}/http.p12" ]]; then
    openssl pkcs12 -export \
      -inkey "${ES_HTTP_KEY}" \
      -in "${ES_HTTP_CRT}" \
      -certfile "${ES_CA_CRT}" \
      -name es-http \
      -out "${ES_CERT_DIR}/http.p12" \
      -passout pass:
    chown root:elasticsearch "${ES_CERT_DIR}/http.p12"
    chmod 0640 "${ES_CERT_DIR}/http.p12"
  fi
}


deploy_configs(){
  step "7/10 Konfigürasyon dosyaları"

  # --- Elasticsearch ---
  install -d -m 0750 "${ES_CONF_DIR}"
  cp -f "${FILES_DIR}/elasticsearch/elasticsearch.yml" "${ES_CONF_DIR}/elasticsearch.yml"
  chown root:elasticsearch "${ES_CONF_DIR}/elasticsearch.yml"
  chmod 0640 "${ES_CONF_DIR}/elasticsearch.yml"

  # HTTP TLS: PEM satırlarını kaldır, keystore.path ekle/güncelle
  sed -i '/^xpack\.security\.http\.ssl\.certificate:/d'             "${ES_CONF_DIR}/elasticsearch.yml"
  sed -i '/^xpack\.security\.http\.ssl\.key:/d'                     "${ES_CONF_DIR}/elasticsearch.yml"
  sed -i '/^xpack\.security\.http\.ssl\.certificate_authorities:/d' "${ES_CONF_DIR}/elasticsearch.yml"
  if grep -q '^xpack\.security\.http\.ssl\.keystore\.path:' "${ES_CONF_DIR}/elasticsearch.yml"; then
    sed -i 's|^xpack\.security\.http\.ssl\.keystore\.path:.*|xpack.security.http.ssl.keystore.path: "'"${ES_CERT_DIR}/http.p12"'"|' "${ES_CONF_DIR}/elasticsearch.yml"
  else
    printf '\nxpack.security.http.ssl.keystore.path: "%s"\n' "${ES_CERT_DIR}/http.p12" >> "${ES_CONF_DIR}/elasticsearch.yml"
  fi
  # (parolasız oluşturuldu; password satırı eklemiyoruz)

  # --- Kibana ---
  install -d -m 0755 /etc/kibana
  cp -f "${FILES_DIR}/kibana/kibana.yml" "/etc/kibana/kibana.yml"
  chmod 0644 "/etc/kibana/kibana.yml"
  # CA yolu sabitle
  if grep -q '^elasticsearch\.ssl\.certificateAuthorities:' /etc/kibana/kibana.yml; then
    sed -i 's|^elasticsearch\.ssl\.certificateAuthorities:.*|elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/ca.crt"]|' /etc/kibana/kibana.yml
  else
    printf '\nelasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/ca.crt"]\n' >> /etc/kibana/kibana.yml
  fi

  # --- Logstash pipelines ---
  install -d -m 0755 /etc/logstash/conf.d
  cp -f "${FILES_DIR}/logstash/fortigate.conf"     "/etc/logstash/conf.d/fortigate.conf"
  cp -f "${FILES_DIR}/logstash/windows_wef.conf"   "/etc/logstash/conf.d/windows_wef.conf"
  cp -f "${FILES_DIR}/logstash/syslog.conf"        "/etc/logstash/conf.d/syslog.conf"
  cp -f "${FILES_DIR}/logstash/kaspersky.conf"     "/etc/logstash/conf.d/kaspersky.conf"
  chmod 0644 /etc/logstash/conf.d/*.conf
}



start_and_wait_es(){
  step "8/10 Servisleri enable et"
  systemctl enable "${ES_SERVICE}" "${KIBANA_SERVICE}" "${LOGSTASH_SERVICE}"

  step "8/10 Servisleri başlat"
  systemctl start "${ES_SERVICE}" || { journalctl -u elasticsearch -n 50 --no-pager || true; false; }
  systemctl start "${KIBANA_SERVICE}" || { journalctl -u kibana -n 50 --no-pager || true; false; }
  systemctl start "${LOGSTASH_SERVICE}" || { journalctl -u logstash -n 50 --no-pager || true; false; }

  step "8/10 Elasticsearch hazır bekleyiş"
  for _ in {1..60}; do
    if curl -s --cacert "${ES_CA_CRT}" https://localhost:9200 >/dev/null 2>&1; then break; fi
    sleep 2
  done
}

secure_identities(){
  step "9/10 elastic parolasını batch reset"
  local RAW=""; RAW="$("${ES_BIN}/elasticsearch-reset-password" -u elastic -s -b 2>/dev/null || true)"
  if [[ -z "${RAW}" ]]; then
    sleep 5
    RAW="$("${ES_BIN}/elasticsearch-reset-password" -u elastic -s -b 2>/dev/null || true)"
  fi
  ELASTIC_PW="$(echo "${RAW}" | awk '{print $NF}' | tail -n1)"
  [[ -z "${ELASTIC_PW}" ]] && { err "elastic parolası alınamadı."; exit 1; }

  step "9/10 Logstash rol/kullanıcı ve keystore"

  # --- Logstash writer rolü ---
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

  # --- logstash_ingest kullanıcı (POST; gerekirse PUT ile güncelle) ---
  local LS_PW; LS_PW="$(openssl rand -base64 24 | tr -d '\n' | cut -c1-24)"
  if ! curl -s --fail --cacert "${ES_CA_CRT}" -u "elastic:${ELASTIC_PW}" \
        -H 'Content-Type: application/json' -X POST \
        https://localhost:9200/_security/user/logstash_ingest \
        -d "{\"password\":\"${LS_PW}\",\"roles\":[\"logstash_writer\"]}" >/dev/null; then
    curl -s --fail --cacert "${ES_CA_CRT}" -u "elastic:${ELASTIC_PW}" \
      -H 'Content-Type: application/json' -X PUT \
      https://localhost:9200/_security/user/logstash_ingest \
      -d "{\"password\":\"${LS_PW}\",\"roles\":[\"logstash_writer\"]}" >/dev/null || \
      warn "kullanıcı (logstash_ingest) oluşturulamadı/güncellenemedi."
  fi

  # --- Logstash log dizini (log4j RollingFile hatalarını kes) ---
  install -d -m 0755 /var/log/logstash
  chown -R logstash:logstash /var/log/logstash || true

  # --- Keystore: tek parola kaynağı (/etc/default/logstash), non-interactive ---
  local ENV_FILE="/etc/default/logstash"
  [[ -f /etc/sysconfig/logstash && ! -f "${ENV_FILE}" ]] && ENV_FILE="/etc/sysconfig/logstash"
  touch "${ENV_FILE}"; chmod 0600 "${ENV_FILE}"; chown root:root "${ENV_FILE}"

  local KS_PW
  if grep -q '^LOGSTASH_KEYSTORE_PASS=' "${ENV_FILE}"; then
    # shellcheck disable=SC1090
    . "${ENV_FILE}"
    KS_PW="${LOGSTASH_KEYSTORE_PASS}"
  else
    KS_PW="$(openssl rand -base64 24 | tr -d '\n' | cut -c1-24)"
    printf 'LOGSTASH_KEYSTORE_PASS="%s"\n' "${KS_PW}" >> "${ENV_FILE}"
  fi
  export LOGSTASH_KEYSTORE_PASS="${KS_PW}"

  # --- Keystore doğrula; açılamıyorsa yeniden oluştur ---
  local NEED_RECREATE=0
  if [[ -f /etc/logstash/logstash.keystore ]]; then
    /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash list >/dev/null 2>&1 || NEED_RECREATE=1
  else
    NEED_RECREATE=1
  fi
  if [[ "${NEED_RECREATE}" -eq 1 ]]; then
    rm -f /etc/logstash/logstash.keystore
    /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash create >/dev/null
  fi

  # --- ES_PW sırrını ekle (üzerine yaz) ---
  printf '%s\n' "${LS_PW}" | /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash add --force ES_PW >/dev/null

  # --- Sahiplik/izinler ve restart ---
  chown logstash:logstash /etc/logstash/logstash.keystore 2>/dev/null || true
  chmod 0600 /etc/logstash/logstash.keystore 2>/dev/null || true
  systemctl restart "${LOGSTASH_SERVICE}" || { journalctl -u logstash -n 100 --no-pager || true; false; }

  # --- Kibana enrollment token (keystore zorunluluğu sağlandı) ---
  step "9/10 Kibana enrollment token"
  ENROLL_TOKEN="$("${ES_BIN}/elasticsearch-create-enrollment-token" -s kibana 2>&1 | tee /tmp/kbn_token.out || true)"
  if ! echo "${ENROLL_TOKEN}" | grep -Eq '^[A-Za-z0-9_\-]+=*\.[A-Za-z0-9_\-]+=*\.[A-Za-z0-9_\-]+=*$'; then
    warn "Enrollment token ilk denemede alınamadı, ES restart ve tekrar denenecek..."
    systemctl restart "${ES_SERVICE}"
    for _ in {1..30}; do
      curl -s --cacert "${ES_CA_CRT}" https://localhost:9200 >/dev/null 2>&1 && break
      sleep 1
    done
    ENROLL_TOKEN="$("${ES_BIN}/elasticsearch-create-enrollment-token" -s kibana 2>&1 | tee -a /tmp/kbn_token.out || true)"
  fi
}

setup_ilm_templates(){
  step "10/10 ILM (logs-30d) + index template (logs-*-*)"
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
    }' >/dev/null || warn "ILM policy var olabilir."

  curl -s --fail --cacert "${ES_CA_CRT}" -u "elastic:${ELASTIC_PW}" \
    -H 'Content-Type: application/json' -X PUT \
    https://localhost:9200/_index_template/logs-ds-template \
    -d '{
      "index_patterns": ["logs-*-*"],
      "data_stream": {},
      "template": { "settings": { "index.lifecycle.name": "logs-30d" } },
      "priority": 200
    }' >/dev/null || warn "index template var olabilir."
}

maybe_open_firewall(){
  step "UFW kural kontrolü (varsa)"
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow "${KIBANA_PORT}/tcp" || true
    ufw allow "${LS_PORT_FGT}/tcp" || true
    ufw allow "${LS_PORT_WEF}/tcp" || true
    ufw allow "${LS_PORT_SYSLOG}/tcp" || true
    ufw allow "${LS_PORT_SYSLOG}/udp" || true
    ufw allow "${LS_PORT_RFC5424}/tcp" || true
    ufw allow "${LS_PORT_KASP}/tcp" || true
    ufw allow "${LS_PORT_KASP}/udp" || true
  fi
}

print_summary(){
  local IP; IP="$(hostname -I | awk '{print $1}')"
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
  echo "Syslog (RFC5424)      : ${LS_PORT_RFC5424}/tcp"
  echo "Kaspersky             : ${LS_PORT_KASP}/tcp+udp"
  echo "Data Streams          : logs-<dataset>-default (ILM: logs-30d)"
  echo "CA (LS için)          : ${LOGSTASH_ES_CA}"
  echo "========================================================"
}

main(){
  require_root
  msg "Elastic Stack (agentless) kurulum başlıyor..."
  init_env
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