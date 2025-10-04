#!/bin/bash
# Elastic Stack 9.x (Elasticsearch, Kibana, Logstash) Otomatik Kurulum Scripti

### 1. Sistem Hazırlığı
if [ "$(id -u)" != "0" ]; then
  echo "Lütfen bu scripti root olarak çalıştırın." >&2
  exit 1
fi

echo "[*] APT güncelleniyor ve gerekli paketler kuruluyor..."
apt update && apt install -y apt-transport-https curl gnupg jq wget

# Elastic GPG anahtarını ekle
echo "[*] Elastic GPG anahtarı ekleniyor..."
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg

# Elastic APT reposunu ekle
echo "[*] Elastic APT deposu ekleniyor..."
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" > /etc/apt/sources.list.d/elastic-9.x.list
apt update

# 2. Elasticsearch Kurulumu
echo "[*] Elasticsearch kuruluyor..."
DEBIAN_FRONTEND=noninteractive apt install -y elasticsearch

# Elasticsearch yapılandırması
echo "[*] Elasticsearch yapılandırılıyor..."
sed -i 's|#network.host: .*|network.host: 0.0.0.0|' /etc/elasticsearch/elasticsearch.yml
echo "discovery.type: single-node" >> /etc/elasticsearch/elasticsearch.yml

# Elasticsearch veri dizini ve log dizini kontrolü ve oluşturulması
echo "[*] Elasticsearch veri dizini ve log dizini izinleri kontrol ediliyor..."
for dir in "/usr/share/elasticsearch/data" "/usr/share/elasticsearch/logs"; do
    if [ ! -d "$dir" ]; then
        echo "Dizin bulunamadı: $dir. Yeni dizin oluşturuluyor..."
        sudo mkdir -p $dir
    fi
    echo "İzinler ayarlanıyor: $dir"
    sudo chown -R elasticsearch:elasticsearch $dir
    sudo chmod -R 755 $dir
done

# Elasticsearch servisini başlat
echo "[*] Elasticsearch servisi başlatılıyor..."
systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch

# 3. Kibana Kurulumu
echo "[*] Kibana kuruluyor..."
apt install -y kibana

# Kibana yapılandırması
echo "[*] Kibana yapılandırılıyor..."
sed -i 's|#server.host: .*|server.host: "0.0.0.0"|' /etc/kibana/kibana.yml
sed -i "s|#elasticsearch.username: .*|elasticsearch.username: \"elastic\"|" /etc/kibana/kibana.yml
sed -i "s|#elasticsearch.password: .*|elasticsearch.password: \"$ELASTIC_PW\"|" /etc/kibana/kibana.yml

# Kibana servisini başlat
systemctl enable kibana
systemctl start kibana

# Kibana'nın doğru şekilde başlaması için Elasticsearch'un tam başlaması bekleniyor
echo "[*] Kibana başlamadan önce Elasticsearch servisinin tam başlaması için bekleniyor..."
sleep 30

# 4. Logstash Kurulumu
echo "[*] Logstash kuruluyor..."
apt install -y logstash

# Logstash pipeline yapılandırması
echo "[*] Logstash pipeline yapılandırılıyor..."

cat <<'LSCONF' > /etc/logstash/conf.d/01-siem.conf
input {
  beats { port => 5044 }
  udp { port => 514 type => "syslog" }
  tcp { port => 514 type => "syslog" }
}

filter {
  if [type] == "syslog" {
    grok { match => { "message" => "<%{NUMBER:priority}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{HOSTNAME:syslog_hostname} %{DATA:syslog_program}(?:\\[%{POSINT:syslog_pid}\\])?: %{GREEDYDATA:syslog_message}" } }
    date { match => [ "syslog_timestamp", "MMM dd HH:mm:ss", "MMM  d HH:mm:ss" ] }
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

# Elastik şifreyi pipeline'a enjekte et
sed -i "s/__ELASTIC_PW__/$ELASTIC_PW/" /etc/logstash/conf.d/01-siem.conf

# Logstash servisini başlat
systemctl enable logstash
systemctl start logstash

# 5. Kibana Token ve Elasticsearch Şifresi
echo "Elastic 'elastic' kullanıcısının yeni şifresi: $ELASTIC_PW"
echo "Kibana Enrollment Token: $KIBANA_TOKEN"

echo "[*] Kurulum tamamlandı. Elastic Stack (Elasticsearch, Kibana, Logstash) çalışır durumda."
echo "Kibana erişimi: https://<SunucuIP>:5601 - Elastic kullanıcı adı: elastic"
echo "NOT: Kibana ilk açılışta Enrollment Token isteyecektir, yukarıda üretilen token'ı kullanınız."