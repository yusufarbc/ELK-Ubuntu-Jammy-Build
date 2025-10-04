#!/bin/bash

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
sudo apt-get install -y apt-transport-https gnupg2 curl wget jq unzip lsb-release certbot python3-certbot-nginx

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

# Elasticsearch yapılandırma
echo "[*] Elasticsearch yapılandırması yapılıyor..."
sudo bash -c "echo 'network.host: 0.0.0.0' >> /etc/elasticsearch/elasticsearch.yml"
sudo bash -c "echo 'discovery.type: single-node' >> /etc/elasticsearch/elasticsearch.yml"

# Elasticsearch servisini başlatmak
echo "[*] Elasticsearch servisi başlatılıyor..."
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# Kibana kurulumu
echo "[*] Kibana kuruluyor..."
sudo apt-get install -y kibana

# Kibana yapılandırması
echo "[*] Kibana yapılandırması yapılıyor..."
sudo bash -c "echo 'elasticsearch.username: \"elastic\"' >> /etc/kibana/kibana.yml"
sudo bash -c "echo 'elasticsearch.password: \"$ELASTIC_PASSWORD\"' >> /etc/kibana/kibana.yml"
sudo bash -c "echo 'server.host: \"0.0.0.0\"' >> /etc/kibana/kibana.yml"
sudo bash -c "echo 'server.ssl.enabled: true' >> /etc/kibana/kibana.yml"
sudo bash -c "echo 'server.ssl.certificate: /etc/elasticsearch/certs/instance.crt' >> /etc/kibana/kibana.yml"
sudo bash -c "echo 'server.ssl.key: /etc/elasticsearch/certs/instance.key' >> /etc/kibana/kibana.yml"

# Kibana servisini başlatmak
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
    hosts => [\"https://localhost:9200\"]
    index => \"fortigate-logs-%{+YYYY.MM.dd}\"
    user => \"elastic\"
    password => \"$ELASTIC_PASSWORD\"
    ssl => true
    cacert => \"/etc/elasticsearch/certs/http_ca.crt\"
  }
}
" | sudo tee /etc/logstash/conf.d/logstash.conf

# Logstash servisini başlatmak
echo "[*] Logstash servisi başlatılıyor..."
sudo systemctl enable logstash
sudo systemctl start logstash

# Nginx kurulumu
echo "[*] Nginx kuruluyor..."
sudo apt-get install -y nginx

# Nginx yapılandırması
echo "[*] Nginx yapılandırması yapılıyor..."
echo "
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
" | sudo tee /etc/nginx/sites-available/kibana

# Nginx sites-available'ı sites-enabled'a bağlama
echo "[*] Nginx yapılandırması etkinleştiriliyor..."
sudo ln -s /etc/nginx/sites-available/kibana /etc/nginx/sites-enabled/

# Nginx yeniden başlatma
echo "[*] Nginx servisi başlatılıyor..."
sudo systemctl restart nginx

# Let's Encrypt ile SSL sertifikası alalım
echo "[*] Let's Encrypt ile SSL sertifikası alınıyor..."
sudo certbot --nginx -d <Sunucu_IP> --non-interactive --agree-tos -m <email_adresiniz>

# SSL ve HTTPs yapılandırmasını kontrol etme
echo "[*] SSL sertifikası etkinleştirildi ve Nginx yeniden başlatılıyor..."
sudo systemctl restart nginx

# Kibana için Enrollment Token alınıyor
echo "[*] Kibana için Enrollment Token alınıyor..."
KIBANA_ENROLLMENT_TOKEN=$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)
echo "Kibana Enrollment Token: $KIBANA_ENROLLMENT_TOKEN"

# Kibana erişimi bilgileri
echo "[*] Kibana erişimi sağlandı. Aşağıdaki bilgileri kullanarak Kibana'ya erişebilirsiniz."
echo "Kibana erişimi: https://<Sunucu_IP>:5601"
echo "Elastic kullanıcı adı: elastic, Parola: $ELASTIC_PASSWORD"
echo "Kibana Enrollment Token: $KIBANA_ENROLLMENT_TOKEN"