#!/bin/bash

# Elastic Stack (Elasticsearch, Kibana, Logstash) Üretim Ortamı Kurulum Scripti

# 1. Sistem Hazırlığı
if [ "$(id -u)" != "0" ]; then
    echo "Bu scripti root olarak çalıştırmalısınız." >&2
    exit 1
fi

# Paketlerin güncellenmesi ve gerekli bağımlılıkların kurulması
echo "[*] APT güncelleniyor ve gerekli paketler kuruluyor..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y apt-transport-https curl gnupg2 lsb-release openjdk-17-jre-headless nginx jq unzip

# 2. Elastic GPG anahtarını ekle ve APT deposunu yapılandır
echo "[*] Elastic GPG anahtarı ekleniyor..."
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic-archive-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-8.x.list

# Paket listelerini güncelle
sudo apt update

# 3. Elasticsearch Kurulumu
echo "[*] Elasticsearch kuruluyor..."
sudo apt install -y elasticsearch

# Elasticsearch yapılandırması
echo "[*] Elasticsearch yapılandırılıyor..."
sudo sed -i 's|#network.host: .*|network.host: 0.0.0.0|' /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's|#discovery.type:.*|discovery.type: single-node|' /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's|#xpack.security.enabled:.*|xpack.security.enabled: true|' /etc/elasticsearch/elasticsearch.yml

# Elasticsearch için TLS/SSL sertifikası oluşturuluyor
echo "[*] Elasticsearch için TLS/SSL sertifikası oluşturuluyor..."
sudo /usr/share/elasticsearch/bin/elasticsearch-certutil ca --pem -out /etc/elasticsearch/certs/elastic-stack-ca.zip
sudo unzip /etc/elasticsearch/certs/elastic-stack-ca.zip -d /etc/elasticsearch/certs
sudo chown -R elasticsearch:elasticsearch /etc/elasticsearch/certs/

# TLS/SSL yapılandırması
echo "[*] Elasticsearch TLS/SSL yapılandırması yapılıyor..."
sudo sed -i 's|#xpack.security.transport.ssl.enabled:.*|xpack.security.transport.ssl.enabled: true|' /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's|#xpack.security.http.ssl.enabled:.*|xpack.security.http.ssl.enabled: true|' /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's|#xpack.security.http.ssl.keystore.path:.*|xpack.security.http.ssl.keystore.path: "/etc/elasticsearch/certs/elastic-certificates.p12"|' /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's|#xpack.security.http.ssl.truststore.path:.*|xpack.security.http.ssl.truststore.path: "/etc/elasticsearch/certs/elastic-certificates.p12"|' /etc/elasticsearch/elasticsearch.yml

# Elasticsearch servisini başlat
sudo systemctl daemon-reload
sudo systemctl enable --now elasticsearch.service

# 4. Kibana Kurulumu
echo "[*] Kibana kuruluyor..."
sudo apt install -y kibana

# Kibana yapılandırması
echo "[*] Kibana yapılandırılıyor..."
sudo sed -i 's|#server.host:.*|server.host: "0.0.0.0"|' /etc/kibana/kibana.yml
sudo sed -i 's|#elasticsearch.hosts:.*|elasticsearch.hosts: ["https://localhost:9200"]|' /etc/kibana/kibana.yml

# Kibana için uygun service account ve güvenli bağlantı ayarları
echo "[*] Kibana için service account yapılandırması yapılıyor..."
sudo sed -i "s|#elasticsearch.username:.*|elasticsearch.username: \"kibana_system\"|" /etc/kibana/kibana.yml
sudo sed -i "s|#elasticsearch.password:.*|elasticsearch.password: \"${KIBANA_PASSWORD}\"|" /etc/kibana/kibana.yml

# Kibana için TLS/SSL yapılandırması
echo "[*] Kibana için TLS/SSL yapılandırması yapılıyor..."
sudo sed -i 's|#xpack.security.http.ssl.enabled:.*|xpack.security.http.ssl.enabled: true|' /etc/kibana/kibana.yml
sudo sed -i 's|#xpack.security.http.ssl.keystore.path:.*|xpack.security.http.ssl.keystore.path: "/etc/elasticsearch/certs/elastic-certificates.p12"|' /etc/kibana/kibana.yml

# Kibana servisini başlat
sudo systemctl enable --now kibana.service

# 5. Kibana Enrollment Token Alımı
echo "[*] Kibana Enrollment Token alınıyor..."
KIBANA_TOKEN=$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)

if [ -n "$KIBANA_TOKEN" ]; then
  export KIBANA_ENROLLMENT_TOKEN="$KIBANA_TOKEN"
  echo "[*] Kibana Enrollment Token alındı ve ENV değişkenine atandı."
else
  echo "[HATA] Kibana Enrollment Token alınamadı!" >&2
  exit 1
fi

echo "[*] Kibana Enrollment Token: $KIBANA_ENROLLMENT_TOKEN"

# 6. Logstash Kurulumu
echo "[*] Logstash kuruluyor..."
sudo apt install -y logstash

# Logstash pipeline oluşturuluyor
echo "[*] Logstash pipeline yapılandırması yapılıyor..."
cat <<EOL | sudo tee /etc/logstash/conf.d/10-beats-input.conf
input {
  beats {
    port => 5044
  }
}

output {
  elasticsearch {
    hosts => ["https://localhost:9200"]
    index => "logstash-%{+YYYY.MM.dd}"
    user => "kibana_system"
    password => "${KIBANA_PASSWORD}"
    ssl => true
    cacert => "/etc/elasticsearch/certs/http_ca.crt"
  }
}
EOL

# Logstash servisini başlat
sudo systemctl enable --now logstash.service

# 7. Nginx Ters Proxy Yapılandırması
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
}" | sudo tee /etc/nginx/sites-available/kibana

sudo ln -s /etc/nginx/sites-available/kibana /etc/nginx/sites-enabled/
sudo systemctl restart nginx.service

# 8. Sonlandırma ve Erişim Bilgileri
echo "[*] Kurulum tamamlandı. Elastic Stack (Elasticsearch, Kibana, Logstash) başarıyla kuruldu."
echo "Kibana erişimi: https://<Sunucu_IP>:5601 - Elastic kullanıcı adı: kibana_system"
echo "Kibana Enrollment Token: $KIBANA_ENROLLMENT_TOKEN"
