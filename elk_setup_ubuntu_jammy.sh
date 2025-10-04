#!/bin/bash

# ELK Stack için otomatik kurulum scripti

# 1. Gerekli bağımlılıkların kurulması
echo "[*] Gerekli bağımlılıklar kuruluyor..."
sudo apt-get update -y
sudo apt-get install -y apt-transport-https curl wget gnupg2 jq unzip lsb-release

# 2. Elastic GPG anahtarını ekleyip Elastic APT deposunu ekleyelim
echo "[*] Elastic GPG anahtarı ekleniyor..."
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo tee /usr/share/keyrings/elastic-archive-keyring.gpg

echo "[*] Elastic APT deposu ekleniyor..."
echo "deb [signed-by=/usr/share/keyrings/elastic-archive-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# 3. Paket listelerini güncelle
echo "[*] Paket listesi güncelleniyor..."
sudo apt-get update -y

# 4. Elasticsearch ve Kibana kurulumu
echo "[*] Elasticsearch kuruluyor..."
sudo apt-get install -y elasticsearch

echo "[*] Kibana kuruluyor..."
sudo apt-get install -y kibana

# 5. Elasticsearch yapılandırma ayarları
echo "[*] Elasticsearch yapılandırılıyor..."
sudo sed -i 's|#network.host: .*|network.host: 0.0.0.0|' /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's|#http.port: 9200|http.port: 9200|' /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's|#discovery.type: .*|discovery.type: single-node|' /etc/elasticsearch/elasticsearch.yml

# 6. Kibana yapılandırma ayarları
echo "[*] Kibana yapılandırılıyor..."
sudo sed -i 's|#server.host: .*|server.host: "0.0.0.0"|' /etc/kibana/kibana.yml
sudo sed -i "s|#elasticsearch.username: .*|elasticsearch.username: \"elastic\"|" /etc/kibana/kibana.yml
sudo sed -i "s|#elasticsearch.password: .*|elasticsearch.password: \"$ELASTIC_PW\"|" /etc/kibana/kibana.yml

# 7. Kibana ve Elasticsearch servislerini etkinleştirip başlatma
echo "[*] Elasticsearch ve Kibana servisleri etkinleştiriliyor..."
sudo systemctl enable elasticsearch
sudo systemctl enable kibana

echo "[*] Elasticsearch ve Kibana servisleri başlatılıyor..."
sudo systemctl start elasticsearch
sudo systemctl start kibana

# 8. Elasticsearch için SSL/TLS sertifikalarının oluşturulması
echo "[*] Elasticsearch için SSL/TLS sertifikası oluşturuluyor..."
if [ ! -d "/etc/elasticsearch/certs" ]; then
    sudo mkdir -p /etc/elasticsearch/certs
fi
sudo /usr/share/elasticsearch/bin/elasticsearch-certutil ca --pem --no-password --out /etc/elasticsearch/certs/elastic-stack-ca.zip
sudo /usr/share/elasticsearch/bin/elasticsearch-certutil cert --pem --ca /etc/elasticsearch/certs/elastic-stack-ca.zip --no-password --out /etc/elasticsearch/certs/elastic-certificates.zip

# 9. Elasticsearch SSL yapılandırmaları
echo "[*] Elasticsearch SSL yapılandırması yapılıyor..."
sudo bash -c "echo 'xpack.security.transport.ssl.enabled: true' >> /etc/elasticsearch/elasticsearch.yml"
sudo bash -c "echo 'xpack.security.http.ssl.enabled: true' >> /etc/elasticsearch/elasticsearch.yml"
sudo bash -c "echo 'xpack.security.http.ssl.keystore.path: /etc/elasticsearch/certs/elastic-certificates.p12' >> /etc/elasticsearch/elasticsearch.yml"
sudo bash -c "echo 'xpack.security.http.ssl.truststore.path: /etc/elasticsearch/certs/elastic-certificates.p12' >> /etc/elasticsearch/elasticsearch.yml"

# 10. Kibana için Enrollment Token alınıyor
echo "[*] Kibana için Enrollment Token alınıyor..."
KIBANA_TOKEN=$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)
echo "Kibana Enrollment Token: $KIBANA_TOKEN"

# 11. Logstash kurulumu
echo "[*] Logstash kuruluyor..."
sudo apt-get install -y logstash

# 12. Logstash pipeline yapılandırması
echo "[*] Logstash pipeline yapılandırması yapılıyor..."
cat <<EOF | sudo tee /etc/logstash/conf.d/logstash.conf
input {
  beats {
    port => 5044
  }
}

filter {
  grok {
    match => { 'message' => '%{SYSLOGTIMESTAMP} %{SYSLOGHOST} %{DATA:fortigate_message}' }
  }
  kv {
    source => "fortigate_message"
  }
}

output {
  elasticsearch {
    hosts => ["https://localhost:9200"]
    index => "fortigate-logs-%{+YYYY.MM.dd}"
    user => "elastic"
    password => "$ELASTIC_PW"
    ssl => true
    cacert => "/etc/elasticsearch/certs/http_ca.crt"
  }
}
EOF

# 13. Logstash servisini başlatma
echo "[*] Logstash servisi başlatılıyor..."
sudo systemctl enable logstash
sudo systemctl start logstash

# 14. Kibana erişimi bilgilerini yazdırma
echo "[*] ELK Stack (Elasticsearch, Kibana, Logstash) başarıyla kuruldu."
echo "Kibana erişimi: https://<Sunucu_IP>:5601"
echo "Elastic kullanıcı adı: elastic, Parola: $ELASTIC_PW"
echo "Kibana Enrollment Token: $KIBANA_TOKEN"