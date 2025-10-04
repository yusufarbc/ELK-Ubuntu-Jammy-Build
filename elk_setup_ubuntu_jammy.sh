#!/bin/bash
# Elastic SIEM On-Prem Kurulum Scripti

### 1. Sistem Hazırlığı
if [ "$(id -u)" != "0" ]; then
  echo "Lütfen bu scripti root olarak çalıştırın." >&2
  exit 1
fi

echo "[*] APT güncelleniyor ve gerekli paketler kuruluyor..."
apt update && apt install -y apt-transport-https curl gnupg jq

# Elastic APT deposunu ekle
echo "[*] Elastic GPG anahtarı ekleniyor..."
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list

apt update

### 2. Elasticsearch Kurulumu
echo "[*] Elasticsearch kuruluyor..."
DEBIAN_FRONTEND=noninteractive apt install -y elasticsearch

### Elasticsearch için gerekli ayarları yapalım
echo "[*] Elasticsearch yapılandırılıyor..."

# network.host satırını güvenle ekle veya değiştir
ES_YML="/etc/elasticsearch/elasticsearch.yml"
if grep -Eq '^\s*#?\s*network\.host:' "$ES_YML"; then
  sed -ri 's|^\s*#?\s*network\.host:.*|network.host: 0.0.0.0|' "$ES_YML"
else
  echo "network.host: 0.0.0.0" >> "$ES_YML"
fi

# discovery.type: single-node ayarını ekleyelim
grep -q '^discovery.type' "$ES_YML" || echo "discovery.type: single-node" >> "$ES_YML"

# vm.max_map_count ayarını yapalım
if ! sysctl -n vm.max_map_count | grep -q "262144"; then
  echo "vm.max_map_count=262144" > /etc/sysctl.d/99-elasticsearch.conf
  sysctl -w vm.max_map_count=262144 || true
fi

# Elasticsearch limits ayarlarını yapalım
cat > /etc/security/limits.d/99-elasticsearch.conf <<'LIMITS'
elasticsearch soft nofile 65536
elasticsearch hard nofile 65536
elasticsearch soft memlock unlimited
elasticsearch hard memlock unlimited
LIMITS

# Heap memory ayarlarını yapalım (max 32 GB)
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

# bootstrap.memory_lock ayarını yapalım
if grep -Eq '^\s*#?\s*bootstrap\.memory_lock:' "$ES_YML"; then
  sed -ri 's|^\s*#?\s*bootstrap\.memory_lock:.*|bootstrap.memory_lock: true|' "$ES_YML"
else
  echo "bootstrap.memory_lock: true" >> "$ES_YML"
fi

### Elasticsearch servisini başlatalım
echo "[*] Elasticsearch servisi başlatılıyor..."
systemctl daemon-reload
systemctl enable elasticsearch

# Elasticsearch servisini başlatmadan önce health kontrolü yapalım
health_check() {
  curl -s -u "elastic:${ELASTIC_PW}" -k https://localhost:9200/_cluster/health || return 1
  return 0
}

if health_check; then
  systemctl start elasticsearch
  echo "[*] Elasticsearch başlatıldı."
else
  echo "[HATA] Elasticsearch servisi başlatılamadı, Elasticsearch loglarını kontrol edin."
  exit 1
fi

### 3. Kibana Kurulumu
echo "[*] Kibana kuruluyor..."
apt install -y kibana

echo "[*] Kibana yapılandırılıyor..."
sed -i 's|#server.host: .*|server.host: "0.0.0.0"|' /etc/kibana/kibana.yml

# Kibana'ya Elasticsearch bağlantısı ayarları (Opsiyonel)
# sed -i "s|#elasticsearch.username: .*|elasticsearch.username: \"elastic\"|" /etc/kibana/kibana.yml
# sed -i "s|#elasticsearch.password: .*|elasticsearch.password: \"$ELASTIC_PW\"|" /etc/kibana/kibana.yml

systemctl enable kibana
sleep 20
systemctl start kibana

echo "[*] Kibana başarılı bir şekilde başlatıldı. İlk kurulum için tarayıcıdan Kibana'ya erişip enrollment token ve verification code adımlarını tamamlayın."

echo "Elastic 'elastic' kullanıcı yeni şifresi: $ELASTIC_PW"

### 4. Logstash Kurulumu ve Ayarı
echo "[*] Logstash kuruluyor..."
apt install -y logstash

# Basit bir Logstash pipeline oluştur
cat <<'LSCONF' > /etc/logstash/conf.d/00-siem.conf
input {
  beats { port => 5044 }
  udp { port => 514 type => "syslog" }
  tcp { port => 514 type => "syslog" }
}
filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "<%{NUMBER:priority}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{HOSTNAME:syslog_hostname} %{DATA:syslog_program}(?:\\[%{POSINT:syslog_pid}\\])?: %{GREEDYDATA:syslog_message}" }
    }
    date {
      match => [ "syslog_timestamp", "MMM dd HH:mm:ss", "MMM d HH:mm:ss" ]
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

echo "[*] Logstash başarılı bir şekilde başlatıldı."
echo "Kurulum tamamlandı. Elastic Stack (Elasticsearch, Kibana, Logstash) çalışır durumda."
echo "Kibana erişimi: https://<SunucuIP>:5601 - Elastic kullanıcı adı: elastic"
echo "NOT: Kibana ilk açılışta Enrollment Token isteyecektir, yukarıda üretilen token'ı kullanınız."

