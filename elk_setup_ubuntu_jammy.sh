#!/bin/bash
# Elastic SIEM On-Prem Kurulum Scripti

### 1. Sistem Hazırlığı
if [ "$(id -u)" != "0" ]; then
  echo "Lütfen bu scripti root olarak çalıştırın." >&2
  exit 1
fi

## CLI arg handling: --password/-p and --non-interactive
NONINTERACTIVE=false
DRY_RUN=false
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
    *)
      shift
      ;;
  esac
done

if [ "$NONINTERACTIVE" = true ]; then
  export DEBIAN_FRONTEND=noninteractive
  APT_NONINTERACTIVE_OPTS='-y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"'
fi

echo "[*] APT güncelleniyor ve gerekli paketler kuruluyor..."
if [ "$DRY_RUN" = false ]; then
  if [ "$NONINTERACTIVE" = true ]; then
    apt-get update -q
    apt-get install $APT_NONINTERACTIVE_OPTS apt-transport-https curl gnupg jq
  else
    apt update
    apt install -y apt-transport-https curl gnupg jq
  fi
else
  echo "DRY RUN: Skipping apt update/install"
fi

# Elastic APT deposunu ekle
echo "[*] Elastic GPG anahtarı ekleniyor..."
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list
apt update

### 2. Elasticsearch Kurulumu
echo "[*] Elasticsearch kuruluyor..."
DEBIAN_FRONTEND=noninteractive apt install -y elasticsearch

# Elasticsearch ayarları: network.host herkese açık, single-node mode
echo "[*] Elasticsearch yapılandırılıyor..."
sed -i 's|#network.host: .*|network.host: 0.0.0.0|' /etc/elasticsearch/elasticsearch.yml
## Elasticsearch ayarlari: network.host herkese acik, single-node mode
echo "[*] Elasticsearch yapılandırılıyor..."
# If network.host line exists (commented or not), replace it; otherwise append
if grep -q "^\s*#\?\s*network.host" /etc/elasticsearch/elasticsearch.yml; then
  sed -ri "s|^\s*#?\s*network.host:.*|network.host: 0.0.0.0|" /etc/elasticsearch/elasticsearch.yml
else
  echo "network.host: 0.0.0.0" >> /etc/elasticsearch/elasticsearch.yml
fi
if ! grep -q "^discovery.type" /etc/elasticsearch/elasticsearch.yml; then
  echo "discovery.type: single-node" >> /etc/elasticsearch/elasticsearch.yml
fi

# Sistem tuning: single-node için rekomendasyonlar
echo "[*] Sistem ayarları uygulanıyor (vm.max_map_count, limits)..."
# vm.max_map_count
if ! sysctl -n vm.max_map_count | grep -q "262144"; then
  echo "vm.max_map_count=262144" > /etc/sysctl.d/99-elasticsearch.conf
  sysctl -w vm.max_map_count=262144 || true
fi
# limits for elasticsearch user
cat > /etc/security/limits.d/99-elasticsearch.conf <<'LIMITS'
elasticsearch soft nofile 65536
elasticsearch hard nofile 65536
elasticsearch soft memlock unlimited
elasticsearch hard memlock unlimited
LIMITS

# Configure JVM heap to be ~50% of RAM (capped at 32768m)
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

# Ensure bootstrap.memory_lock is set in elasticsearch.yml
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
  echo "[*] Elastic parola kaynağı tespit edildi (env/secret/arg). Parola görüntülenmeyecektir."
else
  echo "[*] Elastic kullanıcı şifresi yok — otomatik oluşturma deneniyor..."
  if ELASTIC_PW_OUT=$(yes | /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b 2>/dev/null) && echo "$ELASTIC_PW_OUT" | grep -q "New value:"; then
    ELASTIC_PW="$(echo "$ELASTIC_PW_OUT" | awk '/New value:/ {print $NF}')"
    # Güvenli saklama: sadece root okur
    echo "$ELASTIC_PW" > /root/.elastic_pw
    chmod 600 /root/.elastic_pw
    echo "[*] Yeni 'elastic' parolası /root/.elastic_pw dosyasına kaydedildi (chmod 600)."
  else
    if [ "$NONINTERACTIVE" = true ]; then
      echo "Otomatik şifre sıfırlama başarısız ve non-interactive modda işlem durduruluyor. Lütfen ELASTIC_PASSWORD ortam değişkeni veya --password arg verin." >&2
      exit 1
    fi
    echo "Otomatik şifre sıfırlama başarısız oldu; lütfen manuel olarak bir parola belirleyin." >&2
    read -rsp "Elastic kullanıcısı için yeni parola girin: " ELASTIC_PW
    echo
    # manuel girildiğinde de güvenli dosyaya kaydet
    echo "$ELASTIC_PW" > /root/.elastic_pw
    chmod 600 /root/.elastic_pw
    echo "[*] Girilen parola /root/.elastic_pw dosyasına kaydedildi (chmod 600)."
  fi
fi

# Kibana enrollment token al
echo "[*] Kibana için enrollment token alınıyor..."
KIBANA_TOKEN="$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)"
echo "Kibana Enrollment Token: $KIBANA_TOKEN"

# (Not: Yukarıdaki token, Kibana'yı elle enroll etmek için kullanılacak. 
# Script, Kibana enrollment işlemini otomatik yapmamaktadır.)

### 3. Kibana Kurulumu
echo "[*] Kibana kuruluyor..."
if [ "$DRY_RUN" = false ]; then
  apt install -y kibana
else
  echo "DRY RUN: apt install -y kibana (skipped)"
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

echo "Kibana başarılı bir şekilde başlatıldı. İlk kurulum için tarayıcıdan Kibana'ya erişip enrollment token ve verification code adımlarını tamamlayın."
echo "Elastic 'elastic' kullanıcı yeni şifresi: $ELASTIC_PW"

### 4. Logstash Kurulumu ve Ayarı
echo "[*] Logstash kuruluyor..."
if [ "$DRY_RUN" = false ]; then
  apt install -y logstash
else
  echo "DRY RUN: apt install -y logstash (skipped)"
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

echo "Kurulum tamamlandı. Elastic Stack (Elasticsearch, Kibana, Logstash) çalışır durumda."
echo "Kibana erişimi: https://<SunucuIP>:5601 - Elastic kullanıcı adı: elastic"
echo "NOT: Kibana ilk açılışta Enrollment Token isteyecektir, yukarıda üretilen tokenı kullanınız."
