#!/bin/bash
# Elastic SIEM On-Prem Kurulum Scripti (Düzeltilmiş - Kibana Enrollment Token ENV olarak)

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

# Elasticsearch ayarları: network.host herkese açık, single-node mode
echo "[*] Elasticsearch yapılandırılıyor..."
sed -i 's|#network.host: .*|network.host: 0.0.0.0|' /etc/elasticsearch/elasticsearch.yml
if ! grep -q "^discovery.type" /etc/elasticsearch/elasticsearch.yml; then
  echo "discovery.type: single-node" >> /etc/elasticsearch/elasticsearch.yml
fi

# Elasticsearch servisini başlat
systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch

### 3. Elastic 'elastic' kullanıcısı için parola oluşturuluyor
echo "[*] Elastic 'elastic' kullanıcısı için parola oluşturuluyor..."
ELASTIC_PW="$(yes | /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b 2>/dev/null | awk '/New value:/ {print $NF}')"
echo "Yeni 'elastic' şifresi: $ELASTIC_PW"

### 4. Kibana enrollment token alınıyor ve ENV değişkenine atanıyor
echo "[*] Kibana için enrollment token alınıyor..."
KIBANA_TOKEN="$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)"

if [ -n "$KIBANA_TOKEN" ]; then
  export KIBANA_ENROLLMENT_TOKEN="$KIBANA_TOKEN"
  echo "[*] Kibana Enrollment Token alındı ve ENV değişkenine atandı."
else
  echo "[HATA] Kibana Enrollment Token alınamadı!" >&2
  exit 1
fi

# (Not: Yukarıdaki token, Kibana'yı elle enroll etmek için kullanılacak.
# Script, Kibana enrollment işlemini otomatik yapmamaktadır.)

### 5. Kibana Kurulumu
echo "[*] Kibana kuruluyor..."
apt install -y kibana

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

### 6. Logstash Kurulumu ve Ayarı
echo "[*] Logstash kuruluyor..."
apt install -y logstash

# Basit bir Logstash pipeline oluştur
cat <<'LSCONF' > /etc/logstash/conf.d/00-siem.conf
input {
  beats {
    port => 5044
  }
  udp {
    port => 514
    type => "syslog"
  }
  tcp {
    port => 514
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

### 7. Kibana Enrollment Token'ı ekrana basma
echo "[*] Kibana Enrollment Token: $KIBANA_ENROLLMENT_TOKEN"
