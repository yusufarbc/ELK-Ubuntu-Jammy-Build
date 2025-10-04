#!/bin/bash

# Zorunlu değişkenler
export DEBIAN_FRONTEND=noninteractive
export ELASTIC_PASSWORD=$(openssl rand -base64 16)
export KIBANA_PASSWORD=$(openssl rand -base64 16)

# Elasticsearch ve Kibana için parola üretimi
echo "Elastic kullanıcı parolası: $ELASTIC_PASSWORD"
echo "Kibana kullanıcı parolası: $KIBANA_PASSWORD"

# Paketlerin güncellenmesi
echo "[*] Paket listesi güncelleniyor..."
sudo apt-get update -y

# Gerekli bağımlılıkların kurulması
echo "[*] Gerekli bağımlılıklar kuruluyor..."
sudo apt-get install -y apt-transport-https ca-certificates wget curl gnupg2 unzip jq lsb-release

# Elastic GPG anahtarının eklenmesi
echo "[*] Elastic GPG anahtarı ekleniyor..."
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo tee /usr/share/keyrings/elastic-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic-archive-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-8.x.list

# Elasticsearch kurulumu
echo "[*] Elasticsearch kuruluyor..."
sudo apt-get update -y
sudo apt-get install -y elasticsearch

# Elasticsearch yapılandırma ayarları
echo "[*] Elasticsearch yapılandırılıyor..."
sed -i 's|#network.host: .*|network.host: 0.0.0.0|' /etc/elasticsearch/elasticsearch.yml
sed -i 's|#http.port: 9200|http.port: 9200|' /etc/elasticsearch/elasticsearch.yml
sed -i 's|#discovery.type: .*|discovery.type: single-node|' /etc/elasticsearch/elasticsearch.yml

# Elasticsearch servisini başlat
echo "[*] Elasticsearch servisi başlatılıyor..."
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# Elastic kullanıcı şifresinin sıfırlanması
echo "[*] Elastic kullanıcı şifresi sıfırlanıyor..."
ELASTIC_PW="$(yes | /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b 2>/dev/null | awk '/New value:/ {print $NF}')"
echo "Yeni 'elastic' şifresi: $ELASTIC_PW"

# Kibana için enrollment token alınması
echo "[*] Kibana için enrollment token alınıyor..."
KIBANA_TOKEN="$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)"
echo "Kibana Enrollment Token: $KIBANA_TOKEN"

# Kibana kurulumu
echo "[*] Kibana kuruluyor..."
sudo apt-get install -y kibana

# Kibana yapılandırma ayarları
echo "[*] Kibana yapılandırılıyor..."
sed -i 's|#server.host: .*|server.host: "0.0.0.0"|' /etc/kibana/kibana.yml
sed -i "s|#elasticsearch.username: .*|elasticsearch.username: \"elastic\"|" /etc/kibana/kibana.yml
sed -i "s|#elasticsearch.password: .*|elasticsearch.password: \"$ELASTIC_PW\"|" /etc/kibana/kibana.yml
sed -i "s|#xpack.security.enabled: false|xpack.security.enabled: true|" /etc/kibana/kibana.yml
sed -i "s|#server.ssl.enabled: false|server.ssl.enabled: true|" /etc/kibana/kibana.yml
sed -i "s|#server.ssl.certificate: .*|server.ssl.certificate: /etc/elasticsearch/certs/elastic-certificates.crt|" /etc/kibana/kibana.yml
sed -i "s|#server.ssl.key: .*|server.ssl.key: /etc/elasticsearch/certs/elastic-certificates.key|" /etc/kibana/kibana.yml
sed -i "s|#xpack.security.encryptionKey: .*|xpack.security.encryptionKey: \"$KIBANA_PASSWORD\"|" /etc/kibana/kibana.yml

# Kibana servisini başlat
echo "[*] Kibana servisi başlatılıyor..."
sudo systemctl enable kibana
sudo systemctl start kibana

# Logstash kurulumu
echo "[*] Logstash kuruluyor..."
sudo apt-get install -y logstash

# Logstash pipeline yapılandırması
echo "[*] Logstash pipeline yapılandırması yapılıyor..."
echo "
input {
  beats {
    port => 5044
  }
}

output {
  elasticsearch {
    hosts => [\"https://localhost:9200\"]
    index => \"logstash-%{+YYYY.MM.dd}\"
    user => \"elastic\"
    password => \"$ELASTIC_PW\"
    ssl => true
    cacert => \"/etc/elasticsearch/certs/http_ca.crt\"
  }
}
" | sudo tee /etc/logstash/conf.d/logstash.conf

# Logstash servisini başlat
echo "[*] Logstash servisi başlatılıyor..."
sudo systemctl enable logstash
sudo systemctl start logstash

# Kurulum tamamlandı
echo "[*] ELK Stack (Elasticsearch, Kibana, Logstash) başarıyla kuruldu."
echo "Kibana erişimi: https://<Sunucu_IP>:5601 - Elastic kullanıcı adı: elastic, Parola: $ELASTIC_PW"
echo "Kibana Enrollment Token: $KIBANA_TOKEN"