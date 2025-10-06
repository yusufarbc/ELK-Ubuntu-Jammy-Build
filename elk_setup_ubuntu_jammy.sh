#!/usr/bin/env bash
# ==============================================================================
# Elastic Stack (Agentless) — Ubuntu 22.04 Jammy Otomatik Kurulum Script'i
# ==============================================================================
# AMAÇ
#   - Orta ölçekli kurumlar için **agentless** (Elastic Agent/Fleet kullanılmadan)
#     Elastic Stack kurulumu ve temel SIEM altyapısının dakikalar içinde,
#     **tek komutla**, **etkileşimsiz** ve **güvenli** olarak hayata geçirilmesi.
#
# BİLEŞENLER / TOPOLOJİ
#   - Elasticsearch: 127.0.0.1:9200 (yalnızca localhost), **TLS etkin**
#       * HTTP katmanı: PKCS#12 keystore (http.p12) — sertifika & anahtar script ile üretilir
#       * Transport katmanı: PEM sertifikalar (CA, crt, key) — script ile üretilir
#       * Güvenlik: xpack.security.enabled = true
#       * Enrollment: xpack.security.enrollment.enabled = true (token üretimi için)
#   - Kibana: 0.0.0.0:5601 (dışa açık), ES’e CA ile güvenli bağlantı
#   - Logstash: dışa açık input’lar
#       * Beats (FortiGate vb.): 5044/tcp
#       * WEF/Winlogbeat (WEC sunucusundan): 5045/tcp
#       * Syslog RFC3164: 5514/tcp+udp
#       * Syslog RFC5424: 5515/tcp
#       * Kaspersky (syslog varsayımı): 5516/tcp+udp
#
# LOGSTASH PIPELINES (ECS’e yakın normalizasyon)
#   - fortigate.conf     : beats → grok/kv → ECS alan eşleştirme → Elasticsearch
#   - windows_wef.conf   : Winlogbeat (WEF/WEC) → enrich (translate sözlük) → Elasticsearch
#   - syslog.conf        : RFC3164 & RFC5424 ayrıştırma → Elasticsearch
#   - kaspersky.conf     : basit grok ayrıştırma → Elasticsearch
#   - translate sözlüğü  : windows_event_codes.yml (4624/4625 vb. kod açıklamaları)
#
# SERTİFİKA MİMARİSİ
#   - CA (ca.crt / ca.key), HTTP (http.crt/key + http.p12), Transport (transport.crt/key)
#   - SAN seti yalnızca localhost/IP’lerdir: 127.0.0.1, ::1, "localhost"
#   - http.p12 parolasız üretilir (enrollment token aracı gerektirir)
#
# KİLİT DAVRANIŞLAR
#   - **Idempotent** tasarım: tekrar çalıştırılabilir; gereksiz/çakışan ayarları temizler
#   - Hizmetler systemd ile enable/start edilir; başarısızlıkta günlükler ekrana dökülür
#   - Logstash keystore **non-interactive** oluşturulur (parola /etc/default/logstash içine yazılır)
#   - Enrollment token script sonunda otomatik üretilir (gerekirse ES yeniden başlatılır)
#
# İNDEKS YÖNETİMİ (ILM)
#   - ILM politikası: **logs-90d** (90 günde sil)
#   - Varsayılan şablon: logs-*-* / fortigate-logs-* (1 shard, 0 replica, ILM=logs-90d)
#
# DESTEKLENEN SÜRÜM/DAĞITIM
#   - Ubuntu 22.04 LTS (Jammy)
#   - Elastic 8.x (apt reposundan en güncel 8.x; script testleri 8.19.x ile uyumlu)
#
# GÜVENLİK NOTLARI
#   - Elasticsearch yalnızca localhost’ta dinler; dışa açılmaz
#   - Kibana & Logstash dışa açık çalışır; uygun **firewall (UFW/Security Group)** kuralı şarttır
#   - Script, mevcut /etc/elasticsearch, /etc/kibana, /etc/logstash altında **uyumlu**
#     dosyaları üzerine yazar; özelleştirmeleriniz varsa yedek alınız
#
# GEREKSİNİMLER
#   - root veya sudo yetkisi
#   - İnternet erişimi (Elastic APT deposu)
#
# KULLANIM
#   git clone https://github.com/yusufarbc/ELK-Ubuntu-Jammy-Build.git
#   cd ELK-Ubuntu-Jammy-Build
#   chmod +x elk_setup_ubuntu_jammy.sh
#   sudo ./elk_setup_ubuntu_jammy.sh
#
# ÇIKTI / BİLGİ
#   - Kibana URL, elastic parolası, enrollment token, Logstash giriş portları ve CA yolları
#     kurulum sonunda özet olarak yazdırılır
#
# HATA TEŞHİSİ
#   - Başarısız bir adımda script systemd günlüklerinden son kayıtları basar:
#       journalctl -u elasticsearch -n 200 --no-pager
#       journalctl -u kibana -n 200 --no-pager
#       journalctl -u logstash -n 200 --no-pager
#
# TELİF / LİSANS
#   - Bu script “as is” sağlanır; üretim ortamlarında uygulamadan önce test ediniz.
#   - Elastic lisans ve Basic kısıtları geçerlidir; ayrıntılar için elastic.co lisanslarını inceleyin.
# ============================================================================== 


set -Eeuo pipefail

########################
# Genel değişkenler
########################
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

# Durum/özet
ELASTIC_PW=""
ENROLL_TOKEN=""

########################
# Yardımcılar
########################
ts(){ date '+%H:%M:%S'; }
step(){ echo -e "→ $1"; export LAST_STEP="$1"; }
info(){ echo -e "[+] $*"; }
warn(){ echo -e "[!] $*" >&2; }
err() { echo -e "[-] $*" >&2; }
die() {
  err "Hata adımında düştü: '${LAST_STEP:-başlangıç}'"
  echo "----- elasticsearch journal (son 50) -----"; journalctl -u "${ES_SERVICE}" -n 50 --no-pager || true
  echo "----- kibana journal (son 50) -----------"; journalctl -u "${KIBANA_SERVICE}" -n 50 --no-pager || true
  echo "----- logstash journal (son 50) ---------"; journalctl -u "${LOGSTASH_SERVICE}" -n 50 --no-pager || true
  exit 1
}
trap die ERR

########################
# 0) Ortam hazırlık
########################
prepare_env(){
  step "0/10 Ortam hazırlanıyor"
  [[ $EUID -ne 0 ]] && { err "Lütfen root/sudo ile çalıştırın."; exit 1; }
  export DEBIAN_FRONTEND=noninteractive
}

########################
# 1) APT repo ve bağımlılıklar
########################
setup_repos(){
  step "1/10 APT deposu ve bağımlılıklar"

  apt-get update -y
  apt-get install -y --no-install-recommends \
    lsb-release ca-certificates coreutils curl gpg wget jq unzip apt-transport-https

  install -d -m 0755 /etc/apt/keyrings

  # Elastic keyring
  if [[ ! -s /etc/apt/keyrings/elastic.gpg ]]; then
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /etc/apt/keyrings/elastic.gpg
    info "Elastic GPG anahtarı eklendi: /etc/apt/keyrings/elastic.gpg"
  fi

  # Repo list (duplicate yok)
  cat >/etc/apt/sources.list.d/elastic-8.x.list <<'EOF'
deb [signed-by=/etc/apt/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main
EOF

  apt-get update -y
}

########################
# 2) Kernel ayarı
########################
tune_sysctl(){
  step "2/10 vm.max_map_count ayarı"
  sysctl -w vm.max_map_count=262144 >/dev/null
  sed -i '/^vm\.max_map_count/d' /etc/sysctl.conf
  echo "vm.max_map_count=262144" >> /etc/sysctl.conf
}

########################
# 3) Paket kurulumları
########################
install_stack(){
  step "3/10 Elasticsearch, Kibana, Logstash kurulumu"
  apt-get install -y elasticsearch kibana logstash
}

########################
# 4) Dizin ve izinler
########################
prepare_dirs(){
  step "4/10 Dizin ve izinler"
  install -d -m 0750 "${ES_CONF_DIR}"
  install -d -m 0755 "${ES_CERT_DIR}"
  install -d -m 0755 "${ES_LOG_DIR}"
  chown -R root:elasticsearch "${ES_CONF_DIR}" "${ES_CERT_DIR}"
  chown -R elasticsearch:elasticsearch "${ES_LOG_DIR}"

  # Logstash CA dizini
  install -d -m 0755 /etc/logstash/certs
  # Kibana CA dizini
  install -d -m 0755 /etc/kibana/certs
}

########################
# 5) systemd drop-in (ES_PATH_CONF/ES_LOG_DIR)
########################
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

########################
# 6) Sertifikalar (CA + HTTP + Transport) & http.p12
########################
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

  # instances.yml (yalnız localhost)
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

  # HTTP (PEM)
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

  # Transport (PEM)
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

  # HTTP için PKCS#12 (Enrollment token aracı bunu ister)
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

  # Logstash ve Kibana için CA kopyaları
  cp -f "${ES_CA_CRT}" "${LOGSTASH_ES_CA}"
  chmod 0644 "${LOGSTASH_ES_CA}"
  cp -f "${ES_CA_CRT}" /etc/kibana/certs/ca.crt
  chmod 0644 /etc/kibana/certs/ca.crt
}

########################
# 7) Konfig dosyaları (ve ES TLS keystore.path)
########################
deploy_configs(){
  step "7/10 Konfigürasyon dosyaları"

  # Elasticsearch
  install -d -m 0750 "${ES_CONF_DIR}"
  cp -f "${FILES_DIR}/elasticsearch/elasticsearch.yml" "${ES_CONF_DIR}/elasticsearch.yml"
  chown root:elasticsearch "${ES_CONF_DIR}/elasticsearch.yml"
  chmod 0640 "${ES_CONF_DIR}/elasticsearch.yml"

  # ES yalnız localhost
  sed -i '/^network\.host:/d' "${ES_CONF_DIR}/elasticsearch.yml"
  sed -i '/^http\.host:/d' "${ES_CONF_DIR}/elasticsearch.yml"
  printf 'network.host: 127.0.0.1\nhttp.host: 127.0.0.1\n' >> "${ES_CONF_DIR}/elasticsearch.yml"

  # HTTP TLS: PEM satırlarını kaldır, keystore.path ekle/güncelle
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

  # Kibana
  install -d -m 0755 /etc/kibana
  cp -f "${FILES_DIR}/kibana/kibana.yml" "/etc/kibana/kibana.yml"
  chmod 0644 "/etc/kibana/kibana.yml"
  # CA yolu sabit
  if grep -q '^elasticsearch\.ssl\.certificateAuthorities:' /etc/kibana/kibana.yml; then
    sed -i 's|^elasticsearch\.ssl\.certificateAuthorities:.*|elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/ca.crt"]|' /etc/kibana/kibana.yml
  else
    printf '\nelasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/ca.crt"]\n' >> /etc/kibana/kibana.yml
  fi
  # Kibana encryption keys (uyarıları sustur)
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

  # WEF translate sözlüğü
  install -d -m 0755 /etc/logstash/translate
  cp -f "${FILES_DIR}/logstash/translate/windows_event_codes.yml" /etc/logstash/translate/windows_event_codes.yml
  chmod 0644 /etc/logstash/translate/windows_event_codes.yml
}

########################
# 8) Servisleri enable + start
########################
start_services(){
  step "8/10 Servisleri enable et"
  systemctl enable "${ES_SERVICE}" "${KIBANA_SERVICE}" "${LOGSTASH_SERVICE}"

  step "8/10 Servisleri başlat"
  systemctl daemon-reload
  systemctl restart "${ES_SERVICE}" || true

  # ES hazır bekleyiş
  for _ in {1..60}; do
    if curl -s --cacert "${ES_CA_CRT}" https://localhost:9200 >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  if ! systemctl is-active --quiet "${ES_SERVICE}"; then
    warn "Elasticsearch başlatılamadı, günlükler:"
    journalctl -u "${ES_SERVICE}" -n 200 --no-pager || true
    ESLOG="$(ls -1t ${ES_LOG_DIR}/*.log 2>/dev/null | head -n1 || true)"
    [[ -n "${ESLOG}" ]] && { echo "---- $(basename "${ESLOG}") (tail) ----"; tail -n 200 "${ESLOG}"; }
    exit 1
  fi

  systemctl restart "${KIBANA_SERVICE}" || true
  systemctl restart "${LOGSTASH_SERVICE}" || true
}

########################
# 9) Parolalar, LS keystore, enrollment token
########################
secure_identities(){
  # elastic parolasını batch reset
  step "9/10 elastic parolasını batch reset"
  local RAW=""; RAW="$("${ES_BIN}/elasticsearch-reset-password" -u elastic -s -b 2>/dev/null || true)"
  if [[ -z "${RAW}" ]]; then
    sleep 5
    RAW="$("${ES_BIN}/elasticsearch-reset-password" -u elastic -s -b 2>/dev/null || true)"
  fi
  ELASTIC_PW="$(echo "${RAW}" | awk '{print $NF}' | tail -n1)"
  [[ -z "${ELASTIC_PW}" ]] && { err "elastic parolası alınamadı."; exit 1; }

  # Logstash writer rolü
  step "9/10 Logstash rol/kullanıcı ve keystore"
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

  # logstash_ingest kullanıcı (POST; gerekirse PUT)
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

  # Logstash log dizini ve keystore (non-interactive, idempotent)
  install -d -m 0755 /var/log/logstash
  chown -R logstash:logstash /var/log/logstash || true

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

  # Enrollment token (http.p12 sayesinde çalışır)
  step "9/10 Kibana enrollment token"
  ENROLL_TOKEN="$("${ES_BIN}/elasticsearch-create-enrollment-token" -s kibana 2>&1 || true)"
  if ! echo "${ENROLL_TOKEN}" | grep -Eq '^[A-Za-z0-9_\-]+=*\.[A-Za-z0-9_\-]+=*\.[A-Za-z0-9_\-]+=*$'; then
    warn "Enrollment token ilk denemede alınamadı; ES restart ve tekrar denenecek..."
    systemctl restart "${ES_SERVICE}"
    for _ in {1..40}; do
      curl -s --cacert "${ES_CA_CRT}" https://localhost:9200 >/dev/null 2>&1 && break
      sleep 1
    done
    ENROLL_TOKEN="$("${ES_BIN}/elasticsearch-create-enrollment-token" -s kibana 2>&1 || true)"
  fi
}

########################
# 10) ILM & template
########################
setup_ilm_template(){
  step "10/10 ILM (logs-90d) + index template (logs-*-*)"

  local ILM_NAME="logs-90d"

  # 90 günde silen ILM politikası
  curl -s --fail --cacert "${ES_CA_CRT}" -u "elastic:${ELASTIC_PW}" \
    -H 'Content-Type: application/json' \
    -X PUT "https://localhost:9200/_ilm/policy/${ILM_NAME}" \
    -d '{
      "policy": {
        "phases": {
          "hot":   { "actions": {} },
          "delete":{ "min_age": "90d", "actions": { "delete": {} } }
        }
      }
    }' >/dev/null || warn "ILM policy oluşturulamadı."

  # Varsayılan index template’i 90g ILM ile güncelle
  curl -s --fail --cacert "${ES_CA_CRT}" -u "elastic:${ELASTIC_PW}" \
    -H 'Content-Type: application/json' \
    -X PUT "https://localhost:9200/_index_template/logs-default" \
    -d '{
      "index_patterns": ["logs-*-*","fortigate-logs-*"],
      "template": {
        "settings": {
          "index.lifecycle.name": "'"${ILM_NAME}"'",
          "number_of_shards": 1,
          "number_of_replicas": 0
        },
        "mappings": {
          "_source": { "enabled": true },
          "dynamic": true
        }
      },
      "composed_of": []
    }' >/dev/null || warn "Index template oluşturulamadı."
}

########################
# UFW bilgilendirmesi (opsiyonel)
########################
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

########################
# Özet yazdır
########################
print_summary(){
  cat <<EOF

==================== KURULUM ÖZETİ ====================
Kibana URL            : http://<Sunucu_IP_veya_FQDN>:5601
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


########################
# Çalıştır
########################
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
