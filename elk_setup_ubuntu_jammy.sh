#!/bin/bash

set -e

echo "[*] Paket listesi güncelleniyor..."
sudo apt update -y

# Gerekli Bağımlılıkların Kurulumu
echo "[*] Gerekli bağımlılıklar kuruluyor..."
sudo apt install -y curl wget jq unzip apt-transport-https gnupg2

# Elastic GPG Anahtarının Eklenmesi
echo "[*] Elastic GPG anahtarı ekleniyor..."
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Elastic Repository'sinin Eklenmesi
echo "[*] Elastic paket deposu ekleniyor..."
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-9.x.list

# Paket listelerini tekrar güncelle
echo "[*] Paket listesi tekrar güncelleniyor..."
sudo apt update -y

# Elasticsearch, Kibana ve Logstash Kurulumu
echo "[*] Elasticsearch kuruluyor..."
sudo apt install -y elasticsearch

echo "[*] Kibana kuruluyor..."
sudo apt install -y kibana

echo "[*] Logstash kuruluyor..."
sudo apt install -y logstash

# SSL Sertifikalarının Otomatik Oluşturulması
echo "[*] Elasticsearch için SSL sertifikaları oluşturuluyor..."
sudo mkdir -p /etc/elasticsearch/certs
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/elasticsearch/certs/transport.key -out /etc/elasticsearch/certs/transport.crt -subj "/CN=elasticsearch"
sudo openssl pkcs12 -export -in /etc/elasticsearch/certs/transport.crt -inkey /etc/elasticsearch/certs/transport.key -out /etc/elasticsearch/certs/transport.p12 -name elasticsearch -password pass:changeme

echo "[*] Kibana için SSL sertifikaları oluşturuluyor..."
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/elasticsearch/certs/instance.key -out /etc/elasticsearch/certs/instance.crt -subj "/CN=kibana"
sudo openssl pkcs12 -export -in /etc/elasticsearch/certs/instance.crt -inkey /etc/elasticsearch/certs/instance.key -out /etc/elasticsearch/certs/instance.p12 -name kibana -password pass:changeme

# Elasticsearch ve Kibana için Parola Üretimi
echo "[*] Elasticsearch ve Kibana için güçlü parolalar oluşturuluyor..."
elastic_password=$(openssl rand -base64 16)
kibana_password=$(openssl rand -base64 16)

echo "[*] Elasticsearch parolası: $elastic_password"
echo "[*] Kibana parolası: $kibana_password"

# Elasticsearch Yapılandırma Dosyasının Sıfırdan Oluşturulması
echo "[*] Elasticsearch yapılandırma dosyası sıfırdan oluşturuluyor..."
sudo tee /etc/elasticsearch/elasticsearch.yml <<EOF
# Elasticsearch Configuration

# Enable security features
xpack.security.enabled: true

# Enable encryption for HTTP client connections (Kibana, Logstash, Agents)
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: certs/http.p12

# Enable encryption and mutual authentication between cluster nodes
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.keystore.path: certs/transport.p12
xpack.security.transport.ssl.truststore.path: certs/transport.p12

# Allow connections from any IP (adjust as per your security requirements)
network.host: 0.0.0.0
http.host: 0.0.0.0

# Use single-node discovery (useful for development)
discovery.type: single-node
EOF

# Kibana Yapılandırma Dosyasının Sıfırdan Oluşturulması
echo "[*] Kibana yapılandırma dosyası sıfırdan oluşturuluyor..."
sudo tee /etc/kibana/kibana.yml <<EOF
# Kibana Configuration
server.host: "0.0.0.0"
elasticsearch.username: "elastic"
elasticsearch.password: "$elastic_password"
server.ssl.enabled: true
server.ssl.certificate: /etc/elasticsearch/certs/instance.crt
server.ssl.key: /etc/elasticsearch/certs/instance.key

# Enable enrollment for Kibana
xpack.security.enrollment.enabled: true
EOF

# Logstash Yapılandırması
echo "[*] Logstash yapılandırma dosyası sıfırdan oluşturuluyor..."
sudo tee /etc/logstash/conf.d/fortigate.conf <<EOF
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
    source => 'fortigate_message'
  }
}

output {
  elasticsearch {
    hosts => ["https://localhost:9200"]
    index => "fortigate-logs-%{+YYYY.MM.dd}"
    user => "elastic"
    password => "$elastic_password"
    ssl => true
    cacert => "/etc/elasticsearch/certs/http_ca.crt"
  }
}
EOF

# Elasticsearch ve Kibana Servislerinin Başlatılması
echo "[*] Elasticsearch servisi başlatılıyor..."
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

echo "[*] Kibana servisi başlatılıyor..."
sudo systemctl enable kibana
sudo systemctl start kibana

# Kibana Enrollment Token Alınması
echo "[*] Kibana için Enrollment Token alınıyor..."
enrollment_token=$(sudo /usr/share/kibana/bin/kibana-enrollment --url https://localhost:5601 --username elastic --password "$elastic_password")

echo "[*] Kibana Enrollment Token: $enrollment_token"

# Sonuçların Yazdırılması
echo "[*] ELK Stack kurulumu tamamlandı."
echo "[*] Kibana erişimi: https://$(hostname -I | awk '{print $1}'):5601"
echo "Elastic kullanıcı adı: elastic, Parola: $elastic_password"
echo "Kibana Enrollment Token: $enrollment_token"