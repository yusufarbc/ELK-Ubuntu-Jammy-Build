#!/bin/bash
# Elastic Stack Kurulum Scripti

# Zorunlu değişkenler
export DEBIAN_FRONTEND=noninteractive

# Elasticsearch ve Kibana için parola üretimi
export ELASTIC_PASSWORD=$(openssl rand -base64 16)
export KIBANA_PASSWORD=$(openssl rand -base64 16)

echo "Elastic kullanıcı parolası: $ELASTIC_PASSWORD"
echo "Kibana kullanıcı parolası: $KIBANA_PASSWORD"

# Paketlerin güncellenmesi
echo "[*] Paket listesi güncelleniyor..."
sudo apt-get update -y

# Gerekli bağımlılıkların kurulması
echo "[*] Gerekli bağımlılıklar kuruluyor..."
sudo apt-get install -y apt-transport-https gnupg2 curl wget jq unzip lsb-release nginx

# Elastic GPG anahtarının eklenmesi
echo "[*] Elastic GPG anahtarı ekleniyor..."
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-9.x.list

# Paket listelerinin güncellenmesi
echo "[*] Paket listesi tekrar güncelleniyor..."
sudo apt-get update -y

# Elasticsearch kurulumu
echo "[*] Elasticsearch kuruluyor..."
sudo apt-get install -y elasticsearch

# Elasticsearch yapılandırma dosyasını sıfırdan oluştur
echo "[*] Elasticsearch yapılandırma dosyası sıfırdan oluşturuluyor..."
cat <<EOF | sudo tee /etc/elasticsearch/elasticsearch.yml
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

# Create a new cluster with the current node
cluster.initial_master_nodes: ["node-1"]
EOF

# Elasticsearch servisini başlatmak
echo "[*] Elasticsearch servisi başlatılıyor..."
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# Kibana kurulumu
echo "[*] Kibana kuruluyor..."
sudo apt-get install -y kibana

# Kibana yapılandırma dosyasını sıfırdan oluştur
echo "[*] Kibana yapılandırma dosyası sıfırdan oluşturuluyor..."
cat <<EOF | sudo tee /etc/kibana/kibana.yml
# Kibana Configuration
server.host: "0.0.0.0"
elasticsearch.username: "elastic"
elasticsearch.password: "$ELASTIC_PASSWORD"
server.ssl.enabled: true
server.ssl.certificate: /etc/elasticsearch/certs/instance.crt
server.ssl.key: /etc/elasticsearch/certs/instance.key
EOF

# Kibana servisini başlatmak
echo "[*] Kibana servisi başlatılıyor..."
sudo systemctl enable kibana
sudo systemctl start kibana

# Logstash kurulumu
echo "[*] Logstash kuruluyor..."
sudo apt-get install -y logstash

# Logstash yapılandırma dosyasını sıfırdan oluştur
echo "[*] Logstash yapılandırma dosyası sıfırdan oluşturuluyor..."
cat <<EOF | sudo tee /etc/logstash/conf.d/fortigate.conf
input {
  beats {
    port => 5044
  }
}

filter {
  grok {
    match => { "message" => "%{SYSLOGTIMESTAMP} %{SYSLOGHOST} %{DATA:fortigate_message}" }
  }
}

output {
  elasticsearch {
    hosts => ["https://localhost:9200"]
    index => "fortigate-logs-%{+YYYY.MM.dd}"
    user => "elastic"
    password => "$ELASTIC_PASSWORD"
    ssl => true
    cacert => "/etc/elasticsearch/certs/http_ca.crt"
  }
}
EOF

# Logstash servisini başlatmak
echo "[*] Logstash servisi başlatılıyor..."
sudo systemctl enable logstash
sudo systemctl start logstash

# Nginx kurulumu ve yapılandırması
echo "[*] Nginx kuruluyor..."
sudo apt-get install -y nginx

# Nginx yapılandırması
echo "[*] Nginx yapılandırması yapılıyor..."
cat <<EOF | sudo tee /etc/nginx/sites-available/kibana
server {
    listen 80;
    server_name <Sunucu_IP>;

    location / {
        proxy_pass http://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

# Nginx yapılandırmasını etkinleştir
echo "[*] Nginx yapılandırması etkinleştiriliyor..."
sudo ln -s /etc/nginx/sites-available/kibana /etc/nginx/sites-enabled/
sudo systemctl restart nginx

# Kibana Enrollment Token alınıyor
echo "[*] Kibana için Enrollment Token alınıyor..."
KIBANA_ENROLLMENT_TOKEN=$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)
echo "Kibana Enrollment Token: $KIBANA_ENROLLMENT_TOKEN"

echo "[*] ELK Stack kurulumu tamamlandı."
echo "Kibana erişimi: https://<Sunucu_IP>:5601"
echo "Elastic kullanıcı adı: elastic, Parola: $ELASTIC_PASSWORD"
echo "Kibana Enrollment Token: $KIBANA_ENROLLMENT_TOKEN"