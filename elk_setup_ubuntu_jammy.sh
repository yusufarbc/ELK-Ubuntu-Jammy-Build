#!/bin/bash
# Elastic SIEM On-Prem Kurulum Scripti – Ubuntu LTS, Docker'sız, Tek Host
# Test: Ubuntu 22.04 (Jammy)

set -euo pipefail
IFS=$'\n\t'
trap 'rc=$?; if [ $rc -ne 0 ]; then echo "[HATA] Betik $rc koduyla sonlandı" >&2; fi; exit $rc' EXIT

# ---- Log yardımcıları
DEBUG=${DEBUG:-false}
log()      { local lvl="$1"; shift; printf "[%s] %s\n" "$lvl" "$*"; }
log_info() { log "BILGI" "$*"; }
log_warn() { log "UYARI" "$*"; }
log_err()  { log "HATA " "$*"; }
dbg()      { if [ "${DEBUG}" = "true" ]; then log "DEBUG" "$*"; fi; }

# ---- Retry yardımcı
retry() {
  local max=${1:-5} wait=${2:-5}; shift 2
  local n=0
  until "$@"; do
    n=$((n+1))
    if [ "$n" -ge "$max" ]; then
      log_err "Komut $n denemeden sonra başarısız: $*"
      return 1
    fi
    log_warn "Komut başarısız; ${wait}s sonra tekrar (deneme $n/$max): $*"
    sleep "$wait"
  done
}

# ---- Root kontrolü
if [ "$(id -u)" != "0" ]; then
  echo "Lütfen bu scripti root olarak çalıştırın." >&2; exit 1
fi

# ---- Argümanlar
NONINTERACTIVE=false
DRY_RUN=false
TOKEN_RETRIES=24
TOKEN_WAIT=5
VERIFY=true
BIND_ALL=false              # kurulum sonunda 0.0.0.0'a geçmek için --bind-all
KB_BIND_ALL=true            # Kibana'yı dışa aç (varsayılan true)
ELASTIC_PW=${ELASTIC_PW-""}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -p|--password)     ELASTIC_PW="$2"; shift 2 ;;
    --non-interactive) NONINTERACTIVE=true; shift ;;
    --dry-run)         DRY_RUN=true; shift ;;
    --token-retries)   TOKEN_RETRIES="$2"; shift 2 ;;
    --token-wait)      TOKEN_WAIT="$2"; shift 2 ;;
    --debug)           DEBUG=true; shift ;;
    --no-verify)       VERIFY=false; shift ;;
    --bind-all)        BIND_ALL=true; shift ;;
    --kibana-local)    KB_BIND_ALL=false; shift ;;
    *) log_warn "Bilinmeyen arg: $1 (yok sayıldı)"; shift ;;
  esac
done

# ---- APT seçenekleri (dizi!)
APT_OPTS=()
if [ "$NONINTERACTIVE" = true ]; then
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a
  APT_OPTS=(-y -q)
fi

# ---- Sistem hazırlığı
log_info "APT güncelleniyor ve temel paketler kuruluyor..."
if [ "$DRY_RUN" = false ]; then
  if [ "$NONINTERACTIVE" = true ]; then
    retry 5 5 apt-get update -q
    retry 5 10 apt-get install "${APT_OPTS[@]}" apt-transport-https curl gnupg jq ca-certificates lsof
  else
    retry 5 5 apt update
    retry 5 10 apt install -y apt-transport-https curl gnupg jq ca-certificates lsof
  fi
else
  log_info "DRY RUN: apt update/install atlandı"
fi

# ---- Elastic APT deposu
log_info "Elastic APT deposu ekleniyor..."
install -d /usr/share/keyrings
retry 3 5 bash -c 'curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg'
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list
retry 5 5 apt update

# ---- Elasticsearch kurulumu
log_info "Elasticsearch kuruluyor..."
if [ "$DRY_RUN" = false ]; then
  if [ "$NONINTERACTIVE" = true ]; then
    retry 3 20 apt-get install "${APT_OPTS[@]}" elasticsearch
  else
    retry 3 20 apt install -y elasticsearch
  fi
fi

# ---- ES ayarları
ES_YML="/etc/elasticsearch/elasticsearch.yml"
log_info "Elasticsearch yapılandırılıyor..."

# İlk boot: localhost (bootstrap checks'e takılmasın)
if grep -Eq '^\s*#?\s*network\.host:' "$ES_YML"; then
  sed -ri 's|^\s*#?\s*network\.host:.*|network.host: 127.0.0.1|' "$ES_YML"
else
  echo "network.host: 127.0.0.1" >> "$ES_YML"
fi
# single-node
grep -q '^discovery.type' "$ES_YML" || echo "discovery.type: single-node" >> "$ES_YML"

# ---- Sistem tuning
log_info "Sistem tuning uygulanıyor (vm.max_map_count, limits, heap, memlock/no file/nproc, timeout)..."
# vm.max_map_count
if ! sysctl -n vm.max_map_count | grep -q "262144"; then
  echo "vm.max_map_count=262144" > /etc/sysctl.d/99-elasticsearch.conf
  sysctl -w vm.max_map_count=262144 || true
fi

# limits (pam limits), yine de systemd override asıl kritik
cat > /etc/security/limits.d/99-elasticsearch.conf <<'LIMITS'
elasticsearch soft nofile 65536
elasticsearch hard nofile 65536
elasticsearch soft memlock unlimited
elasticsearch hard memlock unlimited
elasticsearch soft nproc 4096
elasticsearch hard nproc 4096
LIMITS

# Heap (max 32g)
HEAP_MB=1024
if [ -r /proc/meminfo ]; then
  MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo || echo 0)
  if [ "$MEM_KB" -gt 0 ]; then
    MEM_MB=$((MEM_KB/1024))
    HEAP_MB=$((MEM_MB/2))
    [ "$HEAP_MB" -gt 32768 ] && HEAP_MB=32768
  fi
fi

# systemd override: gerçek limitleri burada veriyoruz
install -d /etc/systemd/system/elasticsearch.service.d
cat > /etc/systemd/system/elasticsearch.service.d/override.conf <<EOF
[Service]
Environment="ES_JAVA_OPTS=-Xms${HEAP_MB}m -Xmx${HEAP_MB}m"
LimitMEMLOCK=infinity
LimitNOFILE=65536
LimitNPROC=4096
TimeoutStartSec=900
EOF

# bootstrap.memory_lock
if grep -Eq '^\s*#?\s*bootstrap\.memory_lock:' "$ES_YML"; then
  sed -ri 's|^\s*#?\s*bootstrap\.memory_lock:.*|bootstrap.memory_lock: true|' "$ES_YML"
else
  echo "bootstrap.memory_lock: true" >> "$ES_YML"
fi

# ---- Servisi başlat
systemctl daemon-reload
systemctl enable elasticsearch

log_info "Elasticsearch başlatılıyor..."
if ! systemctl start elasticsearch; then
  log_err "Elasticsearch başlatılamadı. Son loglar:"
  journalctl -u elasticsearch -b --no-pager | tail -n 200 >&2 || true
  exit 1
fi

# ---- Elastic parola
if [ -z "${ELASTIC_PW}" ] && [ -n "${ELASTIC_PASSWORD-}" ]; then
  ELASTIC_PW="$ELASTIC_PASSWORD"
fi
if [ -z "${ELASTIC_PW}" ] && [ -r /run/secrets/elastic_password ]; then
  ELASTIC_PW="$(cat /run/secrets/elastic_password)"
fi

if [ -z "${ELASTIC_PW}" ]; then
  log_info "Elastic şifresi yok — otomatik oluşturma deneniyor..."
  if ELASTIC_PW_OUT=$(yes | /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b 2>/dev/null) && \
     echo "$ELASTIC_PW_OUT" | grep -q "New value:"; then
    ELASTIC_PW="$(echo "$ELASTIC_PW_OUT" | awk '/New value:/ {print $NF}')"
    printf '%s' "$ELASTIC_PW" > /root/.elastic_pw && chmod 600 /root/.elastic_pw
    log_info "Yeni 'elastic' şifresi /root/.elastic_pw dosyasına kaydedildi."
  else
    if [ "$NONINTERACTIVE" = true ]; then
      log_err "Parola otomatik sıfırlanamadı. --password veya ELASTIC_PASSWORD geçiniz."
      exit 1
    fi
    read -rsp "Elastic için yeni parola girin: " ELASTIC_PW; echo
    printf '%s' "$ELASTIC_PW" > /root/.elastic_pw && chmod 600 /root/.elastic_pw
    log_info "Girilen şifre /root/.elastic_pw dosyasına kaydedildi."
  fi
else
  log_info "Elastic şifresi arg/env ile sağlandı."
fi

# ---- Kibana token (ES hazır olana dek dene)
log_info "Kibana enrollment token üretiliyor..."
KIBANA_TOKEN=""
for i in $(seq 1 "$TOKEN_RETRIES"); do
  if systemctl is-active --quiet elasticsearch; then
    HEALTH=$(curl -s -u "elastic:${ELASTIC_PW}" -k https://localhost:9200/_cluster/health || true)
    if echo "$HEALTH" | grep -q '"status"'; then
      if KIBANA_TOKEN_OUT=$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana 2>/dev/null); then
        KIBANA_TOKEN="$KIBANA_TOKEN_OUT"; break
      fi
    fi
  fi
  dbg "ES hazır değil (deneme $i/$TOKEN_RETRIES); ${TOKEN_WAIT}s bekleniyor..."
  sleep "$TOKEN_WAIT"
done
[ -n "$KIBANA_TOKEN" ] && { echo "Kibana Enrollment Token:"; echo "$KIBANA_TOKEN"; } || log_warn "Kibana token şu an oluşturulamadı."

# ---- Kibana kurulumu
log_info "Kibana kuruluyor..."
if [ "$DRY_RUN" = false ]; then
  if [ "$NONINTERACTIVE" = true ]; then
    retry 3 20 apt-get install "${APT_OPTS[@]}" kibana
  else
    retry 3 20 apt install -y kibana
  fi
fi

# Kibana config
KB_YML="/etc/kibana/kibana.yml"
log_info "Kibana yapılandırılıyor..."
if grep -Eq '^\s*#?\s*server\.host:' "$KB_YML"; then
  sed -ri "s|^\s*#?\s*server\.host:.*|server.host: \"$( [ "$KB_BIND_ALL" = true ] && echo 0.0.0.0 || echo 127.0.0.1 )\"|" "$KB_YML"
else
  echo "server.host: \"$( [ "$KB_BIND_ALL" = true ] && echo 0.0.0.0 || echo 127.0.0.1 )\"" >> "$KB_YML"
fi

systemctl enable kibana
sleep 5
if ! systemctl start kibana; then
  log_err "Kibana başlatılamadı. Son loglar:"
  journalctl -u kibana -b --no-pager | tail -n 200 >&2 || true
  exit 1
fi
log_info "Kibana başlatıldı. İlk girişte Enrollment Token + Verification Code gerekecektir."

# ---- Logstash kurulumu
log_info "Logstash kuruluyor..."
if [ "$DRY_RUN" = false ]; then
  if [ "$NONINTERACTIVE" = true ]; then
    retry 3 20 apt-get install "${APT_OPTS[@]}" logstash
  else
    retry 3 20 apt install -y logstash
  fi
fi

# ---- ES HTTP CA cert yolunu bul (LS için)
ES_HTTP_CA=""
for p in \
  /etc/elasticsearch/certs/http_ca.crt \
  /usr/share/elasticsearch/config/certs/http_ca.crt \
  /etc/elasticsearch/http_ca.crt ; do
  [ -f "$p" ] && ES_HTTP_CA="$p" && break
done
if [ -z "$ES_HTTP_CA" ]; then
  log_warn "http_ca.crt bulunamadı; Logstash SSL doğrulamasını disable edeceğim."
fi

# ---- Logstash pipeline
log_info "Logstash pipeline oluşturuluyor..."
install -d /etc/logstash/conf.d
cat <<'LSCONF' > /etc/logstash/conf.d/00-siem.conf
input {
  beats { port => 5044 }          # WEC üstündeki Winlogbeat
  udp   { port => 5514 type => "syslog" }
  tcp   { port => 5514 type => "syslog" }
}
filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "<%{NUMBER:priority}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{HOSTNAME:syslog_hostname} %{DATA:syslog_program}(?:\\[%{POSINT:syslog_pid}\\])?: %{GREEDYDATA:syslog_message}" }
      tag_on_failure => ["_grok_syslog_fail"]
    }
    date {
      match => [ "syslog_timestamp", "MMM dd HH:mm:ss", "MMM  d HH:mm:ss" ]
      target => "@timestamp"
      remove_field => ["syslog_timestamp"]
    }
  }
}
output {
  elasticsearch {
    hosts    => ["https://localhost:9200"]
    index    => "syslog-%{+YYYY.MM.dd}"
    user     => "elastic"
    password => "__ELASTIC_PW__"
    ssl      => true
    # cacert  => "__ES_HTTP_CA__"   # betik mevcutsa doldurur, yoksa ssl_certificate_verification => false
  }
}
LSCONF

# Parola ve CA sertifika enjekte et
escape_sed() { printf '%s' "$1" | sed -e 's/[\\/&]/\\&/g'; }
SAFE_PW="$(escape_sed "$ELASTIC_PW")"
sed -i "s/__ELASTIC_PW__/$SAFE_PW/" /etc/logstash/conf.d/00-siem.conf
if [ -n "$ES_HTTP_CA" ]; then
  SAFE_CA="$(escape_sed "$ES_HTTP_CA")"
  sed -ri "s|^\s*#\s*cacert\s*=>\s*\"__ES_HTTP_CA__\"|    cacert  => \"$SAFE_CA\"|" /etc/logstash/conf.d/00-siem.conf
else
  # CA yoksa doğrulamayı kapat (geçici)
  sed -ri 's|^\s*#\s*cacert\s*=>.*$||' /etc/logstash/conf.d/00-siem.conf
  sed -ri '/ssl\s*=>\s*true/a \ \ \ \ ssl_certificate_verification => false' /etc/logstash/conf.d/00-siem.conf
  log_warn "CA sertifikası bulunamadı; Logstash SSL doğrulaması kapatıldı (geçici)."
fi

systemctl enable logstash
if ! /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t >/dev/null 2>&1; then
  log_err "Logstash config testi başarısız! Lütfen /etc/logstash/conf.d/00-siem.conf dosyasını kontrol edin."
  /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t || true
  exit 1
fi
if ! systemctl start logstash; then
  log_err "Logstash başlatılamadı. Son loglar:"
  journalctl -u logstash -b --no-pager | tail -n 200 >&2 || true
  exit 1
fi

# ---- İsteğe bağlı: ES'i dışa aç (bind-all)
if [ "$BIND_ALL" = true ]; then
  log_info "Elasticsearch dış erişime açılıyor (network.host: 0.0.0.0)..."
  sed -ri 's|^\s*network\.host:.*|network.host: 0.0.0.0|' "$ES_YML"
  systemctl restart elasticsearch || {
    log_err "ES restart başarısız. Son loglar:"; journalctl -u elasticsearch -b --no-pager | tail -n 200 >&2 || true; exit 1; }
fi

# ---- Doğrulamalar
VERIFY_RETRIES=${VERIFY_RETRIES:-12}
VERIFY_WAIT=${VERIFY_WAIT:-5}

check_service_active() {
  local svc="$1"
  if systemctl is-active --quiet "$svc"; then log_info "$svc servisi çalışıyor"; return 0; fi
  log_err "$svc servisi çalışmıyor"; return 1
}
check_es_health() {
  local out
  out=$(curl -s -u "elastic:${ELASTIC_PW}" -k https://localhost:9200/_cluster/health || true)
  echo "$out" | grep -q '"status"' && { log_info "Elasticsearch health OK"; return 0; }
  log_err "Elasticsearch health alınamadı"; return 1
}
check_kibana_up() {
  local code; code=$(curl -s -o /dev/null -w "%{http_code}" -k https://localhost:5601/ || true)
  case "$code" in 200|302|401) log_info "Kibana HTTP OK ($code)"; return 0;; esac
  log_err "Kibana HTTP başarısız ($code)"; return 1
}
check_logstash_config() {
  /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t >/dev/null 2>&1 && \
  { log_info "Logstash config OK"; return 0; } || { log_err "Logstash config hatalı"; return 1; }
}
check_system_settings() {
  local ok=0
  sysctl -n vm.max_map_count | grep -q "262144" && log_info "vm.max_map_count OK" || { log_warn "vm.max_map_count eksik"; ok=1; }
  if command -v runuser >/dev/null 2>&1 && runuser -u elasticsearch -- bash -lc 'ulimit -l' >/dev/null 2>&1; then
    log_info "memlock limiti mevcut"
  else
    log_warn "memlock limiti doğrulanamadı"; ok=1
  fi
  return $ok
}

if [ "$DRY_RUN" = false ] && [ "$VERIFY" = true ]; then
  log_info "Doğrulamalar başlatılıyor..."
  tries=0
  while [ $tries -lt $VERIFY_RETRIES ]; do
    tries=$((tries+1)); fail=0
    check_service_active elasticsearch || fail=1
    check_service_active kibana        || fail=1
    check_service_active logstash      || fail=1
    check_es_health                    || fail=1
    check_kibana_up        || true
    check_logstash_config  || true
    check_system_settings  || true
    [ $fail -eq 0 ] && { log_info "Tüm kritik doğrulamalar başarılı"; break; }
    log_warn "Doğrulama başarısız; $VERIFY_WAIT sn sonra tekrar..."
    sleep "$VERIFY_WAIT"
  done
  [ $fail -eq 0 ] || { log_warn "Bazı doğrulamalar başarısız. Logları inceleyin."; }
fi

echo "Kurulum tamamlandı. Kibana: https://<SunucuIP>:5601  | Kullanıcı: elastic"
[ -n "${KIBANA_TOKEN:-}" ] && echo "Kibana Enrollment Token: ${KIBANA_TOKEN}"
[ -f /root/.elastic_pw ] && echo "Elastic parolası: /root/.elastic_pw (sadece root)"