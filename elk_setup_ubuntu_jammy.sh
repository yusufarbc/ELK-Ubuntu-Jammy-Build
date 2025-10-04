#!/bin/bash

# Zorunlu değişkenler
export DEBIAN_FRONTEND=noninteractive
export ELASTIC_PASSWORD=$(openssl rand -base64 16)  # Elasticsearch için güçlü parola üretimi
export KIBANA_PASSWORD=$(openssl rand -base64 16)  # Kibana için güçlü parola üretimi

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

# Elasticsearch ve Kibana'nın kurulması
echo "[*] Elasticsearch kuruluyor..."
sudo apt-get update -y
sudo apt-get install -y elasticsearch

echo "[*] Kibana kuruluyor..."
sudo apt-get install -y kibana

# Elasticsearch ve Kibana servislerinin etkinleştirilmesi
echo "[*] Elasticsearch ve Kibana servisleri etkinleştiriliyor..."
sudo systemctl enable elasticsearch.service
sudo systemctl enable kibana.service

# Elasticsearch için TLS/SSL sertifikası oluşturulması
echo "[*] Elasticsearch için TLS/SSL sertifikası oluşturuluyor..."
if [ -f /etc/elasticsearch/certs/elastic-stack-ca.zip ]; then
  echo "[*] Sertifika dosyası mevcut, siliniyor..."
  rm -f /etc/elasticsearch/certs/elastic-stack-ca.zip
fi

# Sertifika oluşturuluyor
sudo /usr/share/elasticsearch/bin/elasticsearch-certutil ca --pem --out /etc/elasticsearch/certs/elastic-stack-ca.zip
sudo /usr/share/elasticsearch/bin/elasticsearch-certutil cert --pem --ca /etc/elasticsearch/certs/elastic-stack-ca.zip --out /etc/elasticsearch/certs/elastic-certificates.zip

# Kibana için kullanıcı oluşturulması
echo "[*] Kibana için kullanıcı oluşturuluyor..."
curl -X POST "https://localhost:9200/_security/user/kibana_system" -H "Content-Type: application/json" -u elastic:$ELASTIC_PASSWORD -d "{
  \"password\" : \"$KIBANA_PASSWORD\",
  \"roles\" : [\"kibana_system\"]
}"

# Elasticsearch ve Kibana için SSL yapılandırması
echo "[*] Elasticsearch ve Kibana için SSL/TLS yapılandırması yapılıyor..."
sudo bash -c "echo 'xpack.security.transport.ssl.enabled: true' >> /etc/elasticsearch/elasticsearch.yml"
sudo bash -c "echo 'xpack.security.http.ssl.enabled: true' >> /etc/elasticsearch/elasticsearch.yml"
sudo bash -c "echo 'xpack.security.http.ssl.keystore.path: /etc/elasticsearch/certs/elastic-certificates.p12' >> /etc/elasticsearch/elasticsearch.yml"
sudo bash -c "echo 'xpack.security.http.ssl.truststore.path: /etc/elasticsearch/certs/elastic-certificates.p12' >> /etc/elasticsearch/elasticsearch.yml"

# Kibana yapılandırması
echo "[*] Kibana yapılandırması yapılıyor..."
sudo bash -c "echo 'elasticsearch.username: \"elastic\"' >> /etc/kibana/kibana.yml"
sudo bash -c "echo 'elasticsearch.password: \"$ELASTIC_PASSWORD\"' >> /etc/kibana/kibana.yml"
sudo bash -c "echo 'server.ssl.enabled: true' >> /etc/kibana/kibana.yml"
sudo bash -c "echo 'server.ssl.certificate: /etc/elasticsearch/certs/elastic-certificates.crt' >> /etc/kibana/kibana.yml"
sudo bash -c "echo 'server.ssl.key: /etc/elasticsearch/certs/elastic-certificates.key' >> /etc/kibana/kibana.yml"

# Kibana Enrollment Token alınması
echo "[*] Kibana için Enrollment Token alınıyor..."
KIBANA_TOKEN=$(curl -X POST "https://localhost:9200/_security/enroll/kibana" -u elastic:$ELASTIC_PASSWORD -k)
echo "Kibana Enrollment Token: $KIBANA_TOKEN"

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
    user => \"kibana_system\"
    password => \"$KIBANA_PASSWORD\"
    ssl => true
    cacert => \"/etc/elasticsearch/certs/http_ca.crt\"
  }
}
" | sudo tee /etc/logstash/conf.d/logstash.conf

# Nginx ters proxy yapılandırması
echo "[*] Nginx ters proxy yapılandırması yapılıyor..."
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
sudo ln -s /etc/nginx/sites-available/kibana /etc/nginx/sites-enabled/

# Nginx ve Logstash servislerini etkinleştirme
echo "[*] Nginx ve Logstash servisleri etkinleştiriliyor..."
sudo systemctl restart nginx
sudo systemctl enable nginx
sudo systemctl restart logstash
sudo systemctl enable logstash

# Elasticsearch ve Kibana servislerinin başlatılması
echo "[*] Elasticsearch ve Kibana servisleri başlatılıyor..."
sudo systemctl start elasticsearch
sudo systemctl start kibana

# Kurulum tamamlandı
echo "[*] ELK Stack (Elasticsearch, Kibana, Logstash) başarıyla kuruldu."
echo "Kibana erişimi: https://<Sunucu_IP>:5601 - Elastic kullanıcı adı: elastic, Parola: $ELASTIC_PASSWORD"
echo "Kibana Enrollment Token: $KIBANA_TOKEN"
