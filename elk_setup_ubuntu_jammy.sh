#!/usr/bin/env bash
# Elastic Stack (agentless) — Ubuntu 22.04 (Jammy) Otomatik Kurulum
# ES: https://localhost:9200 (TLS, http.p12); Kibana: 0.0.0.0:5601; Logstash: dışa açık
# WEF/Syslog/Kaspersky/FG pipeline'ları, ILM (30gün), enrollment token üretimi
set -Eeuo pipefail

### Genel
ES_SERVICE="elasticsearch"
KIBANA_SERVICE="kibana"
LOGSTASH_SERVICE="logstash"

FILES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/files"

ES_BIN="/usr/share/elasticsearch/bin"
ES_CONF_DIR="/etc/elasticsearch"
ES_CERT_DIR="${ES_CONF_DIR}/certs"
ES_LOG_DIR="/var/log/elasticsearch"

ES_CA_CRT="${ES_CERT_DIR}/ca.crt"
ES_CA_KEY="${ES_CERT_DIR}/ca.key"
ES_HTTP_CRT="${ES_CERT_DIR}/http.crt"
ES_HTTP_KEY="${ES_CERT_DIR}/http.key"
ES_HTTP_P12="${ES_CERT_DIR}/http.p12"
ES_TRANS_CRT="${ES_CERT_DIR}/transport.crt"
ES_TRANS_KEY="${ES_CERT_DIR}/transport.key"

LOGSTASH_ES_CA="/etc/logstash/certs/ca.crt"

ELASTIC_PW=""
ENROLL_TOKEN=""

ts(){ date '+%H:%M:%S'; }
step(){ echo -e "→ $1"; export LAST_STEP="$1"; }
info(){ echo -e "[+] $*"; }
warn(){ echo -e "[!] $*" >&2; }
err(){  echo -e "[-] $*" >&2; }
die(){
  err "Hata adımında düştü: '${LAST_STEP:-başlangıç}'"
  echo "----- elasticsearch journal (son 50) -----"; journalctl -u "${ES_SERVICE}" -n 50 --no-pager || true
  echo "----- kibana journal (son 50) -----------"; journalctl -u "${KIBANA_SERVICE}" -n 50 --no-pager || true
  echo "----- logstash journal (son 50) ---------"; journalctl -u "${LOGSTASH_SERVICE}" -n 50 --no-pager || true
  exit 1
}
trap die ERR

### Curl yardımcıları
es_curl(){
  # $1: method, $2: path (örn /_cluster/health), $3: data (opsiyonel), $4: auth (opsiyonel "user:pass")
  local m="$1"; shift
  local p="$1"; shift
  local d="${1:-}"; shift || true
  local a="${1:-}"; shift || true
  local args=( -sS --fail --cacert "${ES_CA_CRT}" -X "${m}" "https://localhost:9200${p}" -H 'Content-Type: application/json' )
  [[ -n "$a" ]] && args=( -u "$a" "${args[@]}" )
  [[ -n "$d" ]] && args+=( -d "$d" )
  curl "${args[@]}"
}
es_http_ready(){
  # HTTP katmanı 200/401 dönünce hazır kabul ediyoruz
  for _ in {1..120}; do
    local code
    code=$(curl -sk -o /dev/null -w '%{http_code}' --cacert "${ES_CA_CRT}" https://localhost:9200 || true)
    [[ "$code" == "200" || "$code" == "401" ]] && return 0
    sleep 1
  done
  return 1
}
es_cluster_yellow(){
  # cluster health >= yellow
  for _ in {1..120}; do
    if es_curl GET "/_cluster/health?wait_for_status=yellow&timeout=1s" "" "elastic:${ELASTIC_PW}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}
es_security_ready(){
  # security authenticate endpoint 200 dönünce hazır
  for _ in {1..120}; do
    if es_curl GET "/_security/_authenticate" "" "elastic:${ELASTIC_PW}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

### 0) Ortam
prepare_env(){
  step "0/10 Ortam hazırlanıyor"
  [[ $EUID -ne 0 ]] && { err "Root/sudo ile çalıştırın."; exit 1; }
  export DEBIAN_FRONTEND=noninteractive
}

### 1) Repo & bağımlılıklar
setup_repos(){
  step "1/10 APT deposu ve bağımlılıklar"
  apt-get update -y
  apt-get install -y --no-install-recommends lsb-release ca-certificates coreutils curl gpg wget jq unzip apt-transport-https
  install -d -m 0755 /etc/apt/keyrings
  if [[ ! -s /etc/apt/keyrings/elastic.gpg ]]; then
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /etc/apt/keyrings/elastic.gpg
    info "Elastic GPG anahtarı eklendi: /etc/apt/keyrings/elastic.gpg"
  fi
  cat >/etc/apt/sources.list.d/elastic-8.x.list <<'EOF'
deb [signed-by=/etc/apt/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main
EOF
  apt-get update -y
}

### 2) Kernel ayarı
tune_sysctl(){
  step "2/10 vm.max_map_count ayarı"
  sysctl -w vm.max_map_count=262144 >/dev/null
  sed -i '/^vm\.max_map_count/d' /etc/sysctl.conf
  echo "vm.max_map_count=262144" >> /etc/sysctl.conf
}

### 3) Paketler
install_stack(){
  step "3/10 Elasticsearch, Kibana, Logstash kurulumu"
  apt-get install -y elasticsearch kibana logstash
}

### 4) Dizinler
prepare_dirs(){
  step "4/10 Dizin ve izinler"
  install -d -m 0750 "${ES_CONF_DIR}"
  install -d -m 0755 "${ES_CERT_DIR}"
  install -d -m 0755 "${ES_LOG_DIR}"
  chown -R root:elasticsearch "${ES_CONF_DIR}" "${ES_CERT_DIR}"
  chown -R elasticsearch:elasticsearch "${ES_LOG_DIR}"
  install -d -m 0755 /etc/logstash/certs
  install -d -m 0755 /etc/kibana/certs
}

### 5) systemd drop-in
systemd_dropin(){
  step "5/10 systemd drop-in (ES_PATH_CONF/ES_LOG_DIR)"
  install -d /etc/systemd/system/${ES_SERVICE}.service.d
  cat >/etc/systemd/system/${ES_SERVICE}.service.d/override.conf <<EOF
[Service]
Environment="ES_PATH_CONF=${ES_CONF_DIR}"
Environment="ES_LOG_DIR=${ES_LOG_DIR}"
EOF
  systemctl daemon-reload
}

### 6) Sertifikalar (CA + HTTP/Transport PEM + HTTP P12)
generate_certs(){
  step "6/10 TLS sertifikaları (CA+HTTP+Transport) — SAN=localhost/127.0.0.1/::1"
  # CA
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

  # Instances
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

  # HTTP PEM
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

  # Transport PEM
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

  # HTTP P12 (enrollment için zorunlu)
  if [[ ! -f "${ES_HTTP_P12}" ]]; then
    openssl pkcs12 -export \
      -inkey "${ES_HTTP_KEY}" \
      -in "${ES_HTTP_CRT}" \
      -certfile "${ES_CA_CRT}" \
      -name es-http \
      -out "${ES_HTTP_P12}" \
      -passout pass:
    chown root:elasticsearch "${ES_HTTP_P12}"
    chmod 0640 "${ES_HTTP_P12}"
  fi

  # CA kopyaları
  cp -f "${ES_CA_CRT}" "${LOGSTASH_ES_CA}"
  chmod 0644 "${LOGSTASH_ES_CA}"
  cp -f "${ES_CA_CRT}" /etc/kibana/certs/ca.crt
  chmod 0644 /etc/kibana/certs/ca.crt
}

### 7) Konfigler (ES TLS keystore.path + enrollment.enabled)
deploy_configs(){
  step "7/10 Konfigürasyon dosyaları"
  # ES temel dosya
  install -d -m 0750 "${ES_CONF_DIR}"
  cp -f "${FILES_DIR}/elasticsearch/elasticsearch.yml" "${ES_CONF_DIR}/elasticsearch.yml"
  chown root:elasticsearch "${ES_CONF_DIR}/elasticsearch.yml"
  chmod 0640 "${ES_CONF_DIR}/elasticsearch.yml"

  # ES yalnız localhost
  sed -i '/^network\.host:/d' "${ES_CONF_DIR}/elasticsearch.yml"
  sed -i '/^http\.host:/d' "${ES_CONF_DIR}/elasticsearch.yml"
  printf 'network.host: 127.0.0.1\nhttp.host: 127.0.0.1\n' >> "${ES_CONF_DIR}/elasticsearch.yml"

  # HTTP TLS: PEM satırlarını temizle; keystore.path & client_auth & enrollment
  sed -i '/^xpack\.security\.http\.ssl\.certificate:/d'             "${ES_CONF_DIR}/elasticsearch.yml"
  sed -i '/^xpack\.security\.http\.ssl\.key:/d'                     "${ES_CONF_DIR}/elasticsearch.yml"
  sed -i '/^xpack\.security\.http\.ssl\.certificate_authorities:/d' "${ES_CONF_DIR}/elasticsearch.yml"
  sed -i '/^xpack\.security\.http\.ssl\.truststore\.path:/d'        "${ES_CONF_DIR}/elasticsearch.yml"
  sed -i '/^xpack\.security\.http\.ssl\.truststore\.password:/d'    "${ES_CONF_DIR}/elasticsearch.yml"

  grep -q '^xpack\.security\.http\.ssl\.enabled:' "${ES_CONF_DIR}/elasticsearch.yml" \
    && sed -i 's|^xpack\.security\.http\.ssl\.enabled:.*|xpack.security.http.ssl.enabled: true|' "${ES_CONF_DIR}/elasticsearch.yml" \
    || echo 'xpack.security.http.ssl.enabled: true' >> "${ES_CONF_DIR}/elasticsearch.yml"

  grep -q '^xpack\.security\.http\.ssl\.client_authentication:' "${ES_CONF_DIR}/elasticsearch.yml" \
    && sed -i 's|^xpack\.security\.http\.ssl\.client_authentication:.*|xpack.security.http.ssl.client_authentication: optional|' "${ES_CONF_DIR}/elasticsearch.yml" \
    || echo 'xpack.security.http.ssl.client_authentication: optional' >> "${ES_CONF_DIR}/elasticsearch.yml"

  if grep -q '^xpack\.security\.http\.ssl\.keystore\.path:' "${ES_CONF_DIR}/elasticsearch.yml"; then
    sed -i 's|^xpack\.security\.http\.ssl\.keystore\.path:.*|xpack.security.http.ssl.keystore.path: "'"${ES_HTTP_P12}"'"|' "${ES_CONF_DIR}/elasticsearch.yml"
  else
    printf 'xpack.security.http.ssl.keystore.path: "%s"\n' "${ES_HTTP_P12}" >> "${ES_CONF_DIR}/elasticsearch.yml"
  fi

  # ENROLLMENT ZORUNLU
  if grep -q '^xpack\.security\.enrollment\.enabled:' "${ES_CONF_DIR}/elasticsearch.yml"; then
    sed -i 's|^xpack\.security\.enrollment\.enabled:.*|xpack.security.enrollment.enabled: true|' "${ES_CONF_DIR}/elasticsearch.yml"
  else
    echo 'xpack.security.enrollment.enabled: true' >> "${ES_CONF_DIR}/elasticsearch.yml"
  fi

  # Kibana
  cp -f "${FILES_DIR}/kibana/kibana.yml" "/etc/kibana/kibana.yml"
  chmod 0644 "/etc/kibana/kibana.yml"
  if grep -q '^elasticsearch\.ssl\.certificateAuthorities:' /etc/kibana/kibana.yml; then
    sed -i 's|^elasticsearch\.ssl\.certificateAuthorities:.*|elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/ca.crt"]|' /etc/kibana/kibana.yml
  else
    printf '\nelasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/ca.crt"]\n' >> /etc/kibana/kibana.yml
  fi
  if ! grep -q '^xpack\.security\.encryptionKey:' /etc/kibana/kibana.yml; then
    EK1="$(openssl rand -hex 32)"; EK2="$(openssl rand -hex 32)"; EK3="$(openssl rand -hex 32)"
    {
      echo "xpack.security.encryptionKey: \"${EK1}\""
      echo "xpack.encryptedSavedObjects.encryptionKey: \"${EK2}\""
      echo "xpack.reporting.encryptionKey: \"${EK3}\""
    } >> /etc/kibana/kibana.yml
  fi

  # Logstash pipelines
  install -d -m 0755 /etc/logstash/conf.d
  cp -f "${FILES_DIR}/logstash/fortigate.conf"     "/etc/logstash/conf.d/fortigate.conf"
  cp -f "${FILES_DIR}/logstash/windows_wef.conf"   "/etc/logstash/conf.d/windows_wef.conf"
  cp -f "${FILES_DIR}/logstash/syslog.conf"        "/etc/logstash/conf.d/syslog.conf"
  cp -f "${FILES_DIR}/logstash/kaspersky.conf"     "/etc/logstash/conf.d/kaspersky.conf"
  chmod 0644 /etc/logstash/conf.d/*.conf

  # WEF sözlük
  install -d -m 0755 /etc/logstash/translate
  cp -f "${FILES_DIR}/logstash/translate/windows_event_codes.yml" /etc/logstash/translate/windows_event_codes.yml
  chmod 0644 /etc/logstash/translate/windows_event_codes.yml
}

### 8) Servisler
start_services(){
  step "8/10 Servisleri enable et"
  systemctl enable "${ES_SERVICE}" "${KIBANA_SERVICE}" "${LOGSTASH_SERVICE}"

  step "8/10 Servisleri başlat"
  systemctl daemon-reload
  systemctl restart "${ES_SERVICE}"

  # ES HTTP hazır (TLS/HTTP)
  es_http_ready || { err "Elasticsearch HTTP/TLS hazır olmadı."; exit 1; }

  # Kibana & LS arka planda
  systemctl restart "${KIBANA_SERVICE}" || true
  systemctl restart "${LOGSTASH_SERVICE}" || true
}

### 9) Güvenlik/kimlik & keystore & enrollment
secure_identities(){
  step "9/10 elastic parolasını batch reset"
  # elastic parolasını güvenilir al
  local out=""
  for _ in {1..5}; do
    out="$("${ES_BIN}/elasticsearch-reset-password" -u elastic -s -b 2>/dev/null || true)"
    [[ -n "$out" ]] && break
    sleep 3
  done
  ELASTIC_PW="$(echo "${out}" | awk '{print $NF}' | tail -n1)"
  [[ -z "${ELASTIC_PW}" ]] && { err "elastic parolası alınamadı."; exit 1; }

  # Cluster ve security hazır bekleyiş
  es_cluster_yellow || { err "Cluster health yellow olmadı."; exit 1; }
  es_security_ready || { err "Security API hazır değil."; exit 1; }

  step "9/10 Logstash rol/kullanıcı ve keystore"
  # Rol
  es_curl PUT "/_security/role/logstash_writer" \
    '{"cluster":["monitor"],"indices":[{"names":["logs-*-*","fortigate-logs-*"],"privileges":["create_index","write","create","view_index_metadata"]}]}' \
    "elastic:${ELASTIC_PW}" >/dev/null || warn "rol (logstash_writer) zaten var olabilir."

  # Kullanıcı (POST; yoksa PUT ile güncelle)
  local LS_PW; LS_PW="$(openssl rand -base64 24 | tr -d '\n' | cut -c1-24)"
  if ! es_curl POST "/_security/user/logstash_ingest" "{\"password\":\"${LS_PW}\",\"roles\":[\"logstash_writer\"]}" "elastic:${ELASTIC_PW}" >/dev/null; then
    es_curl PUT "/_security/user/logstash_ingest"  "{\"password\":\"${LS_PW}\",\"roles\":[\"logstash_writer\"]}" "elastic:${ELASTIC_PW}" >/dev/null || warn "kullanıcı oluşturulamadı/güncellenemedi."
  fi

  # Keystore non-interactive
  install -d -m 0755 /var/log/logstash
  chown -R logstash:logstash /var/log/logstash || true

  local ENV_FILE="/etc/default/logstash"
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
  printf '%s\n' "${LS_PW}" | /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash add --force ES_PW >/dev/null
  chown logstash:logstash /etc/logstash/logstash.keystore 2>/dev/null || true
  chmod 0600 /etc/logstash/logstash.keystore 2>/dev/null || true

  systemctl restart "${LOGSTASH_SERVICE}" || { journalctl -u logstash -n 100 --no-pager || true; false; }

  # Enrollment token
  step "9/10 Kibana enrollment token"
  ENROLL_TOKEN="$("${ES_BIN}/elasticsearch-create-enrollment-token" -s kibana 2>&1 || true)"
  if ! echo "${ENROLL_TOKEN}" | grep -Eq '^[A-Za-z0-9_\-]+=*\.[A-Za-z0-9_\-]+=*\.[A-Za-z0-9_\-]+=*$'; then
    warn "Enrollment token ilk denemede alınamadı; ES restart ve tekrar denenecek..."
    systemctl restart "${ES_SERVICE}"
    es_http_ready || true
    ENROLL_TOKEN="$("${ES_BIN}/elasticsearch-create-enrollment-token" -s kibana 2>&1 || true)"
  fi
}

### 10) ILM & Template
setup_ilm_template(){
  step "10/10 ILM (logs-30d) + index template (logs-*-*)"
  # Tekrar health/security kontrol (özellikle yeniden başlatma sonrası)
  es_cluster_yellow || warn "cluster health kontrolü zaman aşımı (ILM aşaması)."
  es_security_ready || warn "security authenticate zaman aşımı (ILM aşaması)."

  es_curl PUT "/_ilm/policy/logs-30d" \
'{
  "policy": {
    "phases": {
      "hot":   { "actions": {} },
      "delete":{ "min_age": "30d", "actions": { "delete": {} } }
    }
  }
}' "elastic:${ELASTIC_PW}" >/dev/null || warn "ILM policy oluşturulamadı."

  es_curl PUT "/_index_template/logs-default" \
'{
  "index_patterns": ["logs-*-*","fortigate-logs-*"],
  "template": {
    "settings": {
      "index.lifecycle.name": "logs-30d",
      "number_of_shards": 1,
      "number_of_replicas": 0
    },
    "mappings": {
      "_source": { "enabled": true },
      "dynamic": true
    }
  },
  "composed_of": []
}' "elastic:${ELASTIC_PW}" >/dev/null || warn "Index template oluşturulamadı."
}

### UFW bilgi
ufw_hint(){
  if command -v ufw >/dev/null 2>&1; then
    echo "→ UFW kural kontrolü (varsa)"
    echo "  * Kibana:   ufw allow 5601/tcp"
    echo "  * Beats:    ufw allow 5044/tcp"
    echo "  * WEF:      ufw allow 5045/tcp"
    echo "  * Syslog:   ufw allow 5514/tcp && ufw allow 5514/udp"
    echo "  * RFC5424:  ufw allow 5515/tcp"
    echo "  * Kaspersky:ufw allow 5516/tcp && ufw allow 5516/udp"
  fi
}

### Özet
print_summary(){
  local IP; IP="$(hostname -I 2>/dev/null | awk '{print $1}' || echo "SERVER_IP")"
  cat <<EOF

==================== KURULUM ÖZETİ ====================
Kibana URL            : http://${IP}:5601
Elasticsearch         : https://localhost:9200  (yalnız localhost)
Elastic kullanıcı     : elastic
Elastic parola        : ${ELASTIC_PW}

Logstash kullanıcı    : logstash_ingest (parola keystore: ES_PW)
FortiGate Beats       : 5044/tcp
WEF (Winlogbeat→LS)   : 5045/tcp
Syslog (RFC3164)      : 5514/tcp+udp
Syslog (RFC5424)      : 5515/tcp
Kaspersky             : 5516/tcp+udp
Data Streams/Index    : logs-<dataset>-default (ILM: logs-30d)
CA (LS için)          : ${LOGSTASH_ES_CA}
Enrollment token      : ${ENROLL_TOKEN}
========================================================
[+] Kurulum tamamlandı.
EOF
}

### Çalıştır
echo "[+] Elastic Stack (agentless) kurulum başlıyor..."
prepare_env
setup_repos
tune_sysctl
install_stack
prepare_dirs
systemd_dropin
generate_certs
deploy_configs
start_services
secure_identities
setup_ilm_template
ufw_hint
print_summary