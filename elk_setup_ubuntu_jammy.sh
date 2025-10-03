#!/bin/bash
# Elastic SIEM On-Prem Kurulum Scripti (Düzeltilmiş ve apt-get arg fix)

set -euo pipefail
IFS=$'\n\t'
trap 'rc=$?; if [ $rc -ne 0 ]; then echo "[HATA] Betik $rc koduyla sonlandı" >&2; fi; exit $rc' EXIT

# --- Log yardımcıları ---
DEBUG=${DEBUG:-false}
log() { local lvl="$1"; shift; printf "[%s] %s\n" "$lvl" "$*"; }
log_info()  { log "BILGI" "$*"; }
log_warn()  { log "UYARI" "$*"; }
log_err()   { log "HATA " "$*"; }
log_debug() { if [ "${DEBUG}" = "true" ]; then log "DEBUG" "$*"; fi; }

# --- Retry yardımcı fonksiyonu ---
retry() {
  local max=${1:-5} wait=${2:-5}; shift 2
  local n=0
  until "$@"; do
    n=$((n+1))
    if [ "$n" -ge "$max" ]; then
      log_err "Komut $n denemeden sonra başarısız oldu: $*"
      return 1
    fi
    log_warn "Komut başarısız; ${wait}s sonra tekrar (deneme $n/$max): $*"
    sleep "$wait"
  done
}

# --- Root kontrolü ---
if [ "$(id -u)" != "0" ]; then
  echo "Lütfen bu scripti root olarak çalıştırın." >&2
  exit 1
fi

# --- Argümanlar ---
NONINTERACTIVE=false
DRY_RUN=false
TOKEN_RETRIES=24
TOKEN_WAIT=5
VERIFY=true
ELASTIC_PW=${ELASTIC_PW-""}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -p|--password)        ELASTIC_PW="$2"; shift 2 ;;
    --non-interactive)    NONINTERACTIVE=true; shift ;;
    --dry-run)            DRY_RUN=true; shift ;;
    --token-retries)      TOKEN_RETRIES="$2"; shift 2 ;;
    --token-wait)         TOKEN_WAIT="$2"; shift 2 ;;
    --debug)              DEBUG=true; shift ;;
    --no-verify)          VERIFY=false; shift ;;
    *)                    log_warn "Bilinmeyen argüman: $1 (yok sayıldı)"; shift ;;
  esac
done

# --- APT seçenekleri (dizi olarak!) ---
APT_OPTS=()
if [ "$NONINTERACTIVE" = true ]; then
  export DEBIAN_FRONTEND=noninteractive
  APT_OPTS=(-y -q)
fi

# --- Sistem hazırlığı ---
log_info "APT güncelleniyor ve temel paketler kuruluyor..."
if [ "$DRY_RUN" = false ]; then
  if [ "$NONINTERACTIVE" = true ]; then
    retry 5 5 apt-get update -q
    retry 5 10 apt-get install "${APT_OPTS[@]}" apt-transport-https curl gnupg jq ca-certificates
  else
    retry 5 5 apt update
    retry 5 10 apt install -y apt-transport-https curl gnupg jq ca-certificates
  fi
else
  log_info "DRY RUN: apt update/install atlanıyor"
fi

# --- Elastic APT deposu ---
log_info "Elastic APT deposu ekleniyor..."
install -d /usr/share/keyrings
retry 3 5 bash -c 'curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg'
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list
retry 5 5 apt update

# --- Elasticsearch kurulumu ---
log_info "Elasticsearch kuruluyor..."
if [ "$DRY_RUN" = false ]; then
  if [ "$NONINTERACTIVE" = true ]; then
    retry 3 20 apt-get install "${APT_OPTS[@]}" elasticsearch
  else
    retry 3 20 apt install -y elasticsearch
  fi
else
  log_info "DRY RUN: elasticsearch kurulumu atlandı"
fi

# --- Elasticsearch ayarları ---
ES_YML="/etc/elasticsearch/elasticsearch.yml"
log_info "Elasticsearch yapılandırılıyor..."
# network.host satırını güvenle ekle/değiştir
if grep -Eq '^\s*#?\s*network\.host:' "$ES_YML"; then
  sed -ri 's|^\s*#?\s*network\.host:.*|network.host: 0.0.0.0|' "$ES_YML"
else
  echo "network.host: 0.0.0.0" >> "$ES_YML"
fi
# discovery.type: single-node yoksa ekle
grep -q '^discovery.type' "$ES_YML" || echo "discovery.type: single-node" >> "$ES_YML"

# --- Sistem tuning ---
log_info "Sistem ayarları uygulanıyor (vm.max_map_count, limits, heap, memlock)..."
# vm.max_map_count
if ! sysctl -n vm.max_map_count | grep -q "262144"; then
  echo "vm.max_map_count=262144" > /etc/sysctl.d/99-elasticsearch.conf
  sysctl -w vm.max_map_count=262144 || true
fi
# limits
cat > /etc/security/limits.d/99-elasticsearch.conf <<'LIMITS'
elasticsearch soft nofile 65536
elasticsearch hard nofile 65536
elasticsearch soft memlock unlimited
elasticsearch hard memlock unlimited
LIMITS

# Heap hesapla (max 32g)
HEAP_MB=1024
if [ -r /proc/meminfo ]; then
  MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo || echo 0)
  if [ "$MEM_KB" -gt 0 ]; then
    MEM_MB=$((MEM_KB/1024))
    HEAP_MB=$((MEM_MB/2))
    [ "$HEAP_MB" -gt 32768 ] && HEAP_MB=32768
  fi
fi
install -d /etc/systemd/system/elasticsearch.service.d
cat > /etc/systemd/system/elasticsearch.service.d/override.conf <<EOF
[Service]
Environment="ES_JAVA_OPTS=-Xms${HEAP_MB}m -Xmx${HEAP_MB}m"
LimitMEMLOCK=infinity
EOF

# bootstrap.memory_lock
if grep -Eq '^\s*#?\s*bootstrap\.memory_lock:' "$ES_YML"; then
  sed -ri 's|^\s*#?\s*bootstrap\.memory_lock:.*|bootstrap.memory_lock: true|' "$ES_YML"
else
  echo "bootstrap.memory_lock: true" >> "$ES_YML"
fi

# Servisi başlat
systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch

# --- Elastic parola belirleme ---
# Öncelik: CLI arg -> ENV ELASTIC_PASSWORD -> /run/secrets/elastic_password -> reset-password
if [ -z "${ELASTIC_PW}" ] && [ -n "${ELASTIC_PASSWORD-}" ]; then
  ELASTIC_PW="$ELASTIC_PASSWORD"
fi
if [ -z "${ELASTIC_PW}" ] && [ -r /run/secrets/elastic_password ]; then
  ELASTIC_PW="$(cat /run/secrets/elastic_password)"
fi

if [ -z "${ELASTIC_PW}" ]; then
  log_info "Elastic kullanıcı şifresi yok — otomatik oluşturma deneniyor..."
  if ELASTIC_PW_OUT=$(yes | /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b 2>/dev/null) && \
     echo "$ELASTIC_PW_OUT" | grep -q "New value:"; then
    ELASTIC_PW="$(echo "$ELASTIC_PW_OUT" | awk '/New value:/ {print $NF}')"
    printf '%s' "$ELASTIC_PW" > /root/.elastic_pw && chmod 600 /root/.elastic_pw
    log_info "Yeni 'elastic' parolası /root/.elastic_pw dosyasına kaydedildi."
  else
    if [ "$NONINTERACTIVE" = true ]; then
      log_err "Parola otomatik sıfırlanamadı. --password veya ELASTIC_PASSWORD ile parola verin."
      exit 1
    fi
    read -rsp "Elastic kullanıcısı için yeni parola girin: " ELASTIC_PW; echo
    printf '%s' "$ELASTIC_PW" > /root/.elastic_pw && chmod 600 /root/.elastic_pw
    log_info "Girilen parola /root/.elastic_pw dosyasına kaydedildi."
  fi
else
  log_info "Elastic parola arg/env ile sağlandı (gizli tutuluyor)."
fi

# --- Kibana enrollment token ---
log_info "Kibana enrollment token oluşturuluyor (Elasticsearch hazır olana dek beklenecek)..."
KIBANA_TOKEN=""
for i in $(seq 1 "$TOKEN_RETRIES"); do
  if systemctl is-active --quiet elasticsearch; then
    HEALTH=$(curl -s -u "elastic:${ELASTIC_PW}" -k https://localhost:9200/_cluster/health || true)
    if echo "$HEALTH" | grep -q '"status"'; then
      if KIBANA_TOKEN_OUT=$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana 2>/dev/null); then
        KIBANA_TOKEN="$KIBANA_TOKEN_OUT"
        break
      fi
    fi
  fi
  log_debug "Elasticsearch henüz hazır değil (deneme $i/$TOKEN_RETRIES); ${TOKEN_WAIT}s bekleniyor..."
  sleep "$TOKEN_WAIT"
done
if [ -n "$KIBANA_TOKEN" ]; then
  echo "Kibana Enrollment Token:"
  echo "$KIBANA_TOKEN"
else
  log_warn "Kibana enrollment token şu an oluşturulamadı. Elasticsearch loglarını kontrol edin."
fi

# --- Kibana kurulumu ---
log_info "Kibana kuruluyor..."
if [ "$DRY_RUN" = false ]; then
  if [ "$NONINTERACTIVE" = true ]; then
    retry 3 20 apt-get install "${APT_OPTS[@]}" kibana
  else
    retry 3 20 apt install -y kibana
  fi
else
  log_info "DRY RUN: kibana kurulumu atlandı"
fi

# Kibana config: server.host satırını güvenle ekle/değiştir
KB_YML="/etc/kibana/kibana.yml"
log_info "Kibana yapılandırılıyor..."
if grep -Eq '^\s*#?\s*server\.host:' "$KB_YML"; then
  sed -ri 's|^\s*#?\s*server\.host:.*|server.host: "0.0.0.0"|' "$KB_YML"
else
  echo 'server.host: "0.0.0.0"' >> "$KB_YML"
fi

systemctl enable kibana
sleep 20
systemctl start kibana
log_info "Kibana başlatıldı. İlk açılışta Enrollment Token ve Verification Code adımlarını tamamlayın."

# --- Logstash kurulumu ---
log_info "Logstash kuruluyor..."
if [ "$DRY_RUN" = false ]; then
  if [ "$NONINTERACTIVE" = true ]; then
    retry 3 20 apt-get install "${APT_OPTS[@]}" logstash
  else
    retry 3 20 apt install -y logstash
  fi
else
  log_info "DRY RUN: logstash kurulumu atlandı"
fi

# Logstash pipeline (syslog 5514, beats 5044)
log_info "Logstash pipeline oluşturuluyor..."
cat <<'LSCONF' > /etc/logstash/conf.d/00-siem.conf
input {
  beats {
    port => 5044
  }
  udp {
    port => 5514
    type => "syslog"
  }
  tcp {
    port => 5514
    type => "syslog"
  }
}
filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "<%{NUMBER:priority}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{HOSTNAME:syslog_hostname} %{DATA:syslog_program}(?:\\[%{POSINT:syslog_pid}\\])?: %{GREEDYDATA:syslog_message}" }
    }
    date {
      match => [ "syslog_timestamp", "MMM dd HH:mm:ss", "MMM  d HH:mm:ss" ]
    }
  }
}
output {
  elasticsearch {
    hosts => ["https://localhost:9200"]
    index => "syslog-%{+YYYY.MM.dd}"
    user => "elastic"
    password => "__ELASTIC_PW__"
    ssl => true
    cacert => "/etc/elasticsearch/certs/http_ca.crt"
  }
}
LSCONF

# ELASTIC_PW'yi sed için kaçır
escape_sed() {
  printf '%s' "$1" | sed -e 's/[\\/&]/\\&/g'
}
SAFE_PW="$(escape_sed "$ELASTIC_PW")"
sed -i "s/__ELASTIC_PW__/$SAFE_PW/" /etc/logstash/conf.d/00-siem.conf

systemctl enable logstash
systemctl start logstash

# --- Doğrulamalar ---
VERIFY_RETRIES=${VERIFY_RETRIES:-12}
VERIFY_WAIT=${VERIFY_WAIT:-5}

check_service_active() {
  local svc="$1"
  if systemctl is-active --quiet "$svc"; then
    log_info "$svc servisi çalışıyor"
    return 0
  else
    log_err "$svc servisi çalışmıyor"
    return 1
  fi
}

check_es_health() {
  local out=""
  out=$(curl -s -u "elastic:${ELASTIC_PW}" -k https://localhost:9200/_cluster/health || true)
  if echo "$out" | grep -q '"status"'; then
    log_info "Elasticsearch cluster sağlık sorgusu başarılı"
    return 0
  fi
  log_err "Elasticsearch sağlık bilgisi alınamadı"
  return 1
}

check_kibana_up() {
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" -k https://localhost:5601/ || true)
  if [ "$code" = "200" ] || [ "$code" = "302" ] || [ "$code" = "401" ]; then
    log_info "Kibana HTTP erişim testi başarılı (kod: $code)"
    return 0
  fi
  log_err "Kibana erişim testi başarısız (kod: $code)"
  return 1
}

check_logstash_config() {
  if [ -x "/usr/share/logstash/bin/logstash" ]; then
    if /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t >/dev/null 2>&1; then
      log_info "Logstash config testi başarılı"
      return 0
    else
      log_err "Logstash config testi başarısız"
      return 1
    fi
  else
    log_warn "Logstash ikili dosyası bulunamadı; config testi atlanıyor"
    return 2
  fi
}

check_system_settings() {
  local ok=0
  if sysctl -n vm.max_map_count | grep -q "262144"; then
    log_info "vm.max_map_count doğru ayarlı"
  else
    log_warn "vm.max_map_count önerilen değerde değil"
    ok=1
  fi
  if command -v runuser >/dev/null 2>&1 && runuser -u elasticsearch -- bash -lc 'ulimit -l' >/dev/null 2>&1; then
    log_info "elasticsearch kullanıcısı için memlock limiti mevcut"
  else
    log_warn "elasticsearch memlock limiti doğrulanamadı"
    ok=1
  fi
  return $ok
}

verify_postinstall() {
  log_info "Kurulum sonrası doğrulamalar başlatılıyor (maks. deneme: $VERIFY_RETRIES)."
  local tries=0
  while [ $tries -lt $VERIFY_RETRIES ]; do
    tries=$((tries+1))
    local fail=0
    check_service_active elasticsearch || fail=1
    check_service_active kibana        || fail=1
    check_service_active logstash      || fail=1
    check_es_health                    || fail=1
    check_kibana_up        || true
    check_logstash_config  || true
    check_system_settings  || true
    if [ $fail -eq 0 ]; then
      log_info "Tüm kritik doğrulamalar başarılı"
      return 0
    fi
    log_warn "Doğrulama başarısız; $VERIFY_WAIT sn sonra tekrar..."
    sleep "$VERIFY_WAIT"
  done
  log_err "Doğrulamalar beklenen sonucu vermedi"
  return 1
}

if [ "$DRY_RUN" = false ] && [ "$VERIFY" = true ]; then
  verify_postinstall || log_warn "Lütfen logları inceleyin (journalctl/systemctl)."
fi

echo "Kurulum tamamlandı. Kibana: https://<SunucuIP>:5601  | Kullanıcı: elastic"
[ -n "${KIBANA_TOKEN}" ] && echo "Kibana Enrollment Token (ilk girişte gerekli): ${KIBANA_TOKEN}"
[ -f /root/.elastic_pw ] && echo "Elastic parolası: /root/.elastic_pw (sadece root)."
