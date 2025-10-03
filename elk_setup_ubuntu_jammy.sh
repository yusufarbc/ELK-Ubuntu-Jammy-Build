#!/bin/bash
# Elastic SIEM On-Prem Kurulum Scripti

# Hızlı çıkış ve güvenli hata işleme
set -euo pipefail
IFS=$'\n\t'

# Çıkış raporu için trap
trap 'rc=$?; if [ $rc -ne 0 ]; then echo "[HATA] Betik $rc koduyla sonlandı" >&2; fi; exit $rc' EXIT

# Kayıt (log) yardımcıları
DEBUG=${DEBUG:-false}
log() { local lvl="$1"; shift; printf "[%s] %s\n" "$lvl" "$*"; }
log_info() { log "BILGI" "$*"; }
log_warn() { log "UYARI" "$*"; }
log_err() { log "HATA" "$*"; }
log_debug() { if [ "${DEBUG}" = "true" ]; then log "DEBUG" "$*"; fi }

# retry yardımcı fonksiyonu: retry <max> <wait> <komut...>
retry() {
  local max=${1:-5} wait=${2:-5}; shift 2
  local n=0
  until "$@"; do
    n=$((n+1))
    if [ "$n" -ge "$max" ]; then
      log_err "Komut $n denemeden sonra başarısız oldu: $*"
      return 1
    fi
    log_warn "Komut başarısız oldu; tekrar deneniyor ($n/$max) ${wait}s sonra..."
    sleep "$wait"
  done
}

### 1. Sistem Hazırlığı
if [ "$(id -u)" != "0" ]; then
  echo "Lütfen bu scripti root olarak çalıştırın." >&2
  exit 1
fi

## CLI arg işleme: --password/-p ve --non-interactive
NONINTERACTIVE=false
DRY_RUN=false
TOKEN_RETRIES=24
TOKEN_WAIT=5
while [ "$#" -gt 0 ]; do
  case "$1" in
    -p|--password)
      ELASTIC_PW="$2"
      shift 2
      ;;
    --non-interactive)
      NONINTERACTIVE=true
        shift
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --token-retries)
      TOKEN_RETRIES="$2"
      shift 2
      ;;
    --token-wait)
      TOKEN_WAIT="$2"
      shift 2
      ;;
    --debug)
      DEBUG=true
      shift
      ;;
    --no-verify)
      VERIFY=false
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [ "$NONINTERACTIVE" = true ]; then
  export DEBIAN_FRONTEND=noninteractive
  APT_NONINTERACTIVE_OPTS='-y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"'
fi

log_info "APT güncelleniyor ve gerekli paketler kuruluyor..."
if [ "$DRY_RUN" = false ]; then
  if [ "$NONINTERACTIVE" = true ]; then
    retry 5 5 apt-get update -q
    retry 5 10 apt-get install $APT_NONINTERACTIVE_OPTS apt-transport-https curl gnupg jq
  else
    retry 5 5 apt update
    retry 5 10 apt install -y apt-transport-https curl gnupg jq
  fi
else
  log_info "DRY RUN: apt update/install atlanıyor"
fi

# Elastic APT deposunu ekle
echo "[*] Elastic GPG anahtarı ekleniyor..."
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list
apt update

### 2. Elasticsearch Kurulumu
log_info "Elasticsearch kuruluyor..."
if [ "$DRY_RUN" = false ]; then
  retry 3 20 DEBIAN_FRONTEND=noninteractive apt install -y elasticsearch
else
  log_info "DRY RUN: apt install -y elasticsearch atlandı"
fi

# Elasticsearch ayarları: network.host herkese açık, single-node modu
echo "[*] Elasticsearch yapılandırılıyor..."
sed -i 's|#network.host: .*|network.host: 0.0.0.0|' /etc/elasticsearch/elasticsearch.yml
## Elasticsearch ayarlari: network.host herkese acik, single-node mode
echo "[*] Elasticsearch yapılandırılıyor..."
# Eğer network.host satırı varsa (yoruma alınmış olsa da) değiştir; yoksa satırı ekle
if grep -q "^\s*#\?\s*network.host" /etc/elasticsearch/elasticsearch.yml; then
  sed -ri "s|^\s*#?\s*network.host:.*|network.host: 0.0.0.0|" /etc/elasticsearch/elasticsearch.yml
else
  echo "network.host: 0.0.0.0" >> /etc/elasticsearch/elasticsearch.yml
fi
if ! grep -q "^discovery.type" /etc/elasticsearch/elasticsearch.yml; then
  echo "discovery.type: single-node" >> /etc/elasticsearch/elasticsearch.yml
fi

# Sistem ayarları (tuning): single-node için önerilen değişiklikler
echo "[*] Sistem ayarları uygulanıyor (vm.max_map_count, limits)..."
# vm.max_map_count (Elasticsearch için önerilen değer)
if ! sysctl -n vm.max_map_count | grep -q "262144"; then
  echo "vm.max_map_count=262144" > /etc/sysctl.d/99-elasticsearch.conf
  sysctl -w vm.max_map_count=262144 || true
fi
# elasticsearch kullanıcısı için limits ayarları
cat > /etc/security/limits.d/99-elasticsearch.conf <<'LIMITS'
elasticsearch soft nofile 65536
elasticsearch hard nofile 65536
elasticsearch soft memlock unlimited
elasticsearch hard memlock unlimited
LIMITS

# JVM heap'i yaklaşık RAM'in %50'si olarak ayarla (maksimum 32768m olarak sınırla)
echo "[*] Elasticsearch JVM heap hesaplanıyor ve systemd override oluşturuluyor..."
if [ -r /proc/meminfo ]; then
  MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
  if [ -n "$MEM_KB" ]; then
    MEM_MB=$((MEM_KB/1024))
    HEAP_MB=$((MEM_MB/2))
    if [ "$HEAP_MB" -gt 32768 ]; then
      HEAP_MB=32768
    fi
  else
    HEAP_MB=1024
  fi
else
  HEAP_MB=1024
fi

mkdir -p /etc/systemd/system/elasticsearch.service.d
cat > /etc/systemd/system/elasticsearch.service.d/override.conf <<EOF
[Service]
Environment="ES_JAVA_OPTS=-Xms${HEAP_MB}m -Xmx${HEAP_MB}m"
LimitMEMLOCK=infinity
EOF

# Elasticsearch için bootstrap.memory_lock ayarının bulunduğundan emin ol
if ! grep -q "^bootstrap.memory_lock" /etc/elasticsearch/elasticsearch.yml; then
  echo "bootstrap.memory_lock: true" >> /etc/elasticsearch/elasticsearch.yml
else
  sed -ri "s|^\s*#?\s*bootstrap.memory_lock:.*|bootstrap.memory_lock: true|" /etc/elasticsearch/elasticsearch.yml
fi

# Elasticsearch servisini başlat
systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch

# Parola kaynağı tercihi: argüman -> ELASTIC_PASSWORD env -> /run/secrets/elastic_password
# Eğer CLI ile verildiyse ELASTIC_PW zaten setlidir. Tercih sırası: ELASTIC_PW (arg) üstte kalır.
if [ -z "${ELASTIC_PW-}" ] && [ -n "${ELASTIC_PASSWORD-}" ]; then
  ELASTIC_PW="$ELASTIC_PASSWORD"
fi
if [ -z "${ELASTIC_PW-}" ] && [ -r /run/secrets/elastic_password ]; then
  ELASTIC_PW="$(cat /run/secrets/elastic_password)"
fi

if [ -n "${ELASTIC_PW-}" ]; then
  log_info "Elastic parola kaynağı tespit edildi (env/secret/arg). Parola görüntülenmeyecektir."
else
  log_info "Elastic kullanıcı şifresi yok — otomatik oluşturma deneniyor..."
  if ELASTIC_PW_OUT=$(yes | /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b 2>/dev/null) && echo "$ELASTIC_PW_OUT" | grep -q "New value:"; then
    ELASTIC_PW="$(echo "$ELASTIC_PW_OUT" | awk '/New value:/ {print $NF}')"
    # Güvenli saklama: sadece root okur
    echo "$ELASTIC_PW" > /root/.elastic_pw
    chmod 600 /root/.elastic_pw
    log_info "[*] Yeni 'elastic' parolası /root/.elastic_pw dosyasına kaydedildi (chmod 600)."
  else
    if [ "$NONINTERACTIVE" = true ]; then
      log_err "Otomatik şifre sıfırlama başarısız ve non-interactive modda işlem durduruluyor. Lütfen ELASTIC_PASSWORD ortam değişkeni veya --password arg verin."
      exit 1
    fi
    log_err "Otomatik şifre sıfırlama başarısız oldu; lütfen manuel olarak bir parola belirleyin." >&2
    read -rsp "Elastic kullanıcısı için yeni parola girin: " ELASTIC_PW
    echo
    # manuel girildiğinde de güvenli dosyaya kaydet
    printf '%s' "$ELASTIC_PW" > /root/.elastic_pw
    chmod 600 /root/.elastic_pw
    log_info "[*] Girilen parola /root/.elastic_pw dosyasına kaydedildi (chmod 600)."
  fi
fi

log_info "Kibana enrollment token oluşturulmaya çalışılıyor (Elasticsearch sağlıklı olana kadar beklenecek)..."
KIBANA_TOKEN=""
for i in $(seq 1 "$TOKEN_RETRIES"); do
  # Servisin aktif olup olmadığını kontrol et
  if systemctl is-active --quiet elasticsearch; then
    # ELASTIC_PW sağlandıysa, onu kullanarak cluster sağlık durumunu kontrol et
    if [ -n "${ELASTIC_PW-}" ]; then
      HEALTH=$(curl -s -u elastic:"$ELASTIC_PW" -k https://localhost:9200/_cluster/health?pretty || true)
    else
      # yetkisiz (authsuz) yerel kontrol dene (güvenlik etkinse başarısız olabilir)
      HEALTH=$(curl -s -k https://localhost:9200/_cluster/health?pretty || true)
    fi

    if echo "$HEALTH" | grep -q "status"; then
      # enrollment token oluşturmayı dene
      if KIBANA_TOKEN_OUT=$( /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana 2>/dev/null ) ; then
        KIBANA_TOKEN="$KIBANA_TOKEN_OUT"
        break
      fi
    fi
  else
    log_warn "Elasticsearch servisi henüz aktif değil (deneme $i/$TOKEN_RETRIES)."
  fi
  sleep $TOKEN_WAIT
done

if [ -n "$KIBANA_TOKEN" ]; then
  echo "Kibana Enrollment Token'ı (kopyalayın ve Kibana kayıt işlemi sırasında kullanın):"
  echo "$KIBANA_TOKEN"
else
  echo "[HATA] Kibana enrollment tokenı oluşturulamadı." >&2
  echo "Aşağıdaki komutları manuel olarak çalıştırıp hataları inceleyin:" >&2
  echo "  sudo systemctl status elasticsearch" >&2
  echo "  sudo journalctl -u elasticsearch -b --no-pager | tail -n 50" >&2
  echo "Manuel olarak token oluşturmak için (elasticsearch çalışır durumda olmalı):" >&2
  echo "  sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana" >&2
fi

# (Not: Yukarıdaki token, Kibana'yı elle kayıt (enroll) etmek için kullanılacak.)
# Script, Kibana enrollment işlemini otomatik yapmamaktadır.

### 3. Kibana Kurulumu
log_info "Kibana kuruluyor..."
if [ "$DRY_RUN" = false ]; then
  retry 3 20 apt install -y kibana
else
  log_info "DRY RUN: apt install -y kibana atlandı"
fi

# Kibana yapılandır: dış erişim izni
echo "[*] Kibana yapılandırılıyor..."
sed -i 's|#server.host: .*|server.host: "0.0.0.0"|' /etc/kibana/kibana.yml

# (Opsiyonel) Kibana ile Elastic bağlantısı için elastic kullanıcı bilgisi ayarı:
# sed -i "s|#elasticsearch.username: .*|elasticsearch.username: \"elastic\"|" /etc/kibana/kibana.yml
# sed -i "s|#elasticsearch.password: .*|elasticsearch.password: \"$ELASTIC_PW\"|" /etc/kibana/kibana.yml

systemctl enable kibana

# Elasticsearch hazır olana kadar bir süre bekle
echo "[*] Kibana başlamadan önce Elasticsearch servisinin tam başlaması için bekleniyor..."
sleep 20

systemctl start kibana

log_info "Kibana başarılı bir şekilde başlatıldı. Tarayıcıdan Kibana'ya erişip kayıt (enroll) adımlarını tamamlayın."
if [ -f /root/.elastic_pw ]; then
  log_info "Elastic 'elastic' parolası /root/.elastic_pw dosyasına kaydedildi (sadece root erişimli)."
else
  log_info "Elastic 'elastic' parolası ortamda sağlandı veya manuel olarak belirlendi (parola konsolda gösterilmeyecektir)."
fi

### 4. Logstash Kurulumu ve Ayarı
log_info "Logstash kuruluyor..."
if [ "$DRY_RUN" = false ]; then
  retry 3 20 apt install -y logstash
else
  log_info "DRY RUN: apt install -y logstash atlandı"
fi

# Basit bir Logstash pipeline oluştur
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

# Elastik şifreyi pipeline'a enjekte et
sed -i "s/__ELASTIC_PW__/$ELASTIC_PW/" /etc/logstash/conf.d/00-siem.conf

# Logstash'i başlat
systemctl enable logstash
systemctl start logstash

# Post-install doğrulama fonksiyonları
VERIFY=${VERIFY:-true}
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
  if [ -n "${ELASTIC_PW-}" ]; then
    out=$(curl -s -u elastic:"$ELASTIC_PW" -k https://localhost:9200/_cluster/health || true)
  else
    out=$(curl -s -k https://localhost:9200/_cluster/health || true)
  fi
  if echo "$out" | grep -q '"status"' ; then
    log_info "Elasticsearch cluster sağlık sorgusu başarılı"
    return 0
  fi
  log_err "Elasticsearch sağlık bilgisi alınamadı"
  return 1
}

check_kibana_up() {
  if command -v curl >/dev/null 2>&1; then
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -k https://localhost:5601/ || true)
    if [ "$code" = "200" ] || [ "$code" = "302" ] || [ "$code" = "401" ]; then
      log_info "Kibana HTTP erişim testi başarılı (kod: $code)"
      return 0
    fi
    log_err "Kibana erişim testi başarısız (kod: $code)"
    return 1
  else
    log_warn "curl yüklü değil; Kibana erişimi atlanıyor"
    return 2
  fi
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
    log_warn "vm.max_map_count önerilen değere ayarlı değil"
    ok=1
  fi
  if sudo -u elasticsearch bash -c 'ulimit -l' >/dev/null 2>&1; then
    log_info "elasticsearch kullanıcısı için memlock limiti mevcut"
  else
    log_warn "elasticsearch kullanıcısı için memlock limiti tespit edilemedi veya ulimit komutu başarısız"
    ok=1
  fi
  return $ok
}

verify_postinstall() {
  log_info "Kurulum sonrası doğrulamalar başlatılıyor (maksimum deneme: $VERIFY_RETRIES)."
  local tries=0
  local all_ok=0
  while [ $tries -lt $VERIFY_RETRIES ]; do
    tries=$((tries+1))
    log_debug "Doğrulama denemesi: $tries/$VERIFY_RETRIES"
    all_ok=0
    check_service_active elasticsearch || all_ok=1
    check_service_active kibana || all_ok=1
    check_service_active logstash || all_ok=1
    check_es_health || all_ok=1
    check_kibana_up || true
    check_logstash_config || true
    check_system_settings || true
    if [ $all_ok -eq 0 ]; then
      log_info "Tüm kritik doğrulamalar başarılı"
      return 0
    fi
    log_warn "Doğrulama başarısız; $VERIFY_WAIT saniye sonra tekrar denenecek..."
    sleep $VERIFY_WAIT
  done
  log_err "Kurulum sonrası doğrulamalar beklenen sonucu vermedi"
  return 1
}

# Sadece DRY_RUN değilse ve doğrulama kapatılmadıysa çalıştır
if [ "$DRY_RUN" = false ] && [ "$VERIFY" = true ]; then
  if ! verify_postinstall; then
    log_warn "Doğrulama adımlarından bazıları başarısız oldu. Lütfen logları inceleyin veya README'deki manuel kontrolleri uygulayın."
  fi
fi

echo "Kurulum tamamlandı. Elastic Stack (Elasticsearch, Kibana, Logstash) çalışır durumda."
echo "Kibana erişimi: https://<SunucuIP>:5601 - Elastic kullanıcı adı: elastic"
echo "UYARI: Kibana ilk açılışta Enrollment Token isteyecektir; yukarıda üretilen token'ı kullanın."
