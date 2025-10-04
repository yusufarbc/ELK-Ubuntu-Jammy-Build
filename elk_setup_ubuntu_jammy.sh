#!/bin/bash
# Elastic Stack Kurulum Scripti

### 1. Sistem Hazırlığı ve Paketlerin Yüklenmesi
if [ "$(id -u)" != "0" ]; then
    echo "Lütfen bu scripti root olarak çalıştırın." >&2
    exit 1
fi
echo "[*] APT güncelleniyor ve gerekli paketler kuruluyor..."
apt update && apt install -y apt-transport-https curl gnupg jq

# Elastic GPG anahtarını ekle
echo "[*] Elastic GPG anahtarı ekleniyor..."
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list
apt update

### 2. Elasticsearch Kurulumu
echo "[*] Elasticsearch kuruluyor..."
apt install -y elasticsearch

# Elasticsearch yapılandırması: Single Node Mode ve dış erişim izni
echo "[*] Elasticsearch yapılandırılıyor..."
sed -i 's|#network.host: .*|network.host: 0.0.0.0|' /etc/elasticsearch/elasticsearch.yml
echo "discovery.type: single-node" >> /etc/elasticsearch/elasticsearch.yml

# Elasticsearch servisini başlat
systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch

# Elastic kullanıcı şifresini resetle
echo "[*] Elastic kullanıcı şifresi sıfırlanıyor..."
ELASTIC_PW="$(yes | /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b 2>/dev/null | awk '/New value:/ {print $NF}')"
echo "Yeni 'elastic' şifresi: $ELASTIC_PW"

### 3. Kibana için Enrollment Token Al
echo "[*] Kibana için Enrollment Token alınıyor..."
KIBANA_TOKEN=$(curl -X POST "https://localhost:9200/_security/service/_enroll" -H "Content-Type: application/json" -d '{"type":"kibana"}' -u "elastic:$ELASTIC_PW" | jq -r '.token')
echo "Kibana Enrollment Token: $KIBANA_TOKEN"

# KIBANA_TOKEN ortam değişkenine kaydediliyor
export KIBANA_TOKEN

### 4. Kibana Kurulumu ve Yapılandırma
echo "[*] Kibana kuruluyor..."
apt install -y kibana

# Kibana yapılandırma: dış erişim izni ve Elasticsearch ile bağlantı
echo "[*] Kibana yapılandırılıyor..."
sed -i 's|#server.host: .*|server.host: "0.0.0.0"|' /etc/kibana/kibana.yml
sed -i "s|#elasticsearch.username: .*|elasticsearch.username: \"kibana_system\"|" /etc/kibana/kibana.yml
sed -i "s|#elasticsearch.password: .*|elasticsearch.password: \"$ELASTIC_PW\"|" /etc/kibana/kibana.yml
sed -i "s|#elasticsearch.apiKey: .*|elasticsearch.apiKey: \"$KIBANA_TOKEN\"|" /etc/kibana/kibana.yml

systemctl enable kibana
echo "[*] Elasticsearch'in tam olarak başlaması için 30 saniye bekleniyor..."
sleep 30
systemctl start kibana

### 5. Logstash Kurulumu
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
            match => [ "syslog_timestamp", "MMM dd HH:mm:ss", "MMM dd yyyy HH:mm:ss" ]
        }
    }
}
output {
    elasticsearch {
        hosts => ["https://localhost:9200"]
        index => "syslog-%{+YYYY.MM.dd}"
        user => "elastic"
        password => "$ELASTIC_PW"
        ssl => true
        cacert => "/etc/elasticsearch/certs/http_ca.crt"
    }
}
LSCONF

# Logstash'i başlat
systemctl enable logstash
systemctl start logstash

echo "Kurulum tamamlandı. Elastic Stack (Elasticsearch, Kibana, Logstash) çalışır durumda."
echo "Kibana erişimi: https://<SunucuIP>:5601 - Elastic kullanıcı adı: elastic"
echo "NOT: Kibana ilk açılışta Enrollment Token isteyecektir, yukarıda üretilen token'ı kullanınız."