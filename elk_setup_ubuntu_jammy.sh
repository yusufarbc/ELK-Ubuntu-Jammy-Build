#!/bin/bash

# Gerekli Bağımlılıkları Yükleme
echo "[*] Gerekli bağımlılıklar kuruluyor..."
sudo apt-get update -y
sudo apt-get install -y apt-transport-https gnupg2 curl wget jq unzip lsb-release

# Elastic GPG Anahtarı Ekleniyor
echo "[*] Elastic GPG anahtarı ekleniyor..."
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo tee /usr/share/keyrings/elasticsearch-keyring.gpg > /dev/null

# Elastic APT Deposu Ekleniyor
echo "[*] Elastic APT deposu ekleniyor..."
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-9.x.list > /dev/null

# Paket Listesi Güncelleniyor
echo "[*] Paket listesi güncelleniyor..."
sudo apt-get update -y

# Elasticsearch Kurulumu
echo "[*] Elasticsearch kuruluyor..."
sudo apt-get install -y elasticsearch

# Kibana Kurulumu
echo "[*] Kibana kuruluyor..."
sudo apt-get install -y kibana

# Logstash Kurulumu
echo "[*] Logstash kuruluyor..."
sudo apt-get install -y logstash

# Elasticsearch Yapılandırma Ayarları
echo "[*] Elasticsearch yapılandırılıyor..."
sudo sed -i 's|#network.host: .*|network.host: 0.0.0.0|' /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's|#http.port: 9200|http.port: 9200|' /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's|#discovery.type: .*|discovery.type: single-node|' /etc/elasticsearch/elasticsearch.yml

# Elasticsearch SSL/TLS Sertifikası Oluşturuluyor (self-signed)
echo "[*] Elasticsearch için SSL/TLS sertifikası oluşturuluyor..."
sudo /usr/share/elasticsearch/bin/elasticsearch-certutil cert --pem --self-signed --out /etc/elasticsearch/certs/elastic-certificates.zip

# Sertifika Dosyalarını Çıkartıyoruz
echo "[*] Sertifikalar çıkarılıyor..."
sudo unzip -o /etc/elasticsearch/certs/elastic-certificates.zip -d /etc/elasticsearch/certs/

# Elasticsearch Servisi Başlatılıyor
echo "[*] Elasticsearch servisi başlatılıyor..."
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# Kibana Yapılandırması
echo "[*] Kibana yapılandırılıyor..."
KIBANA_PASSWORD=$(openssl rand -base64 16)
sudo sed -i 's|#server.host: .*|server.host: "0.0.0.0"|' /etc/kibana/kibana.yml
sudo sed -i "s|#elasticsearch.username: .*|elasticsearch.username: \"elastic\"|" /etc/kibana/kibana.yml
sudo sed -i "s|#elasticsearch.password: .*|elasticsearch.password: \"$KIBANA_PASSWORD\"|" /etc/kibana/kibana.yml

# Kibana Servisi Başlatılıyor
echo "[*] Kibana servisi başlatılıyor..."
sudo systemctl enable kibana
sudo systemctl start kibana

# Logstash Pipeline Yapılandırması
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
    password => \"$KIBANA_PASSWORD\"
    ssl => true
    cacert => \"/etc/elasticsearch/certs/http_ca.crt\"
  }
}
" | sudo tee /etc/logstash/conf.d/logstash.conf > /dev/null

# Logstash Servisi Başlatılıyor
echo "[*] Logstash servisi başlatılıyor..."
sudo systemctl enable logstash
sudo systemctl start logstash

# Kibana için Enrollment Token Alınıyor
echo "[*] Kibana için Enrollment Token alınıyor..."
ENROLLMENT_TOKEN=$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)
echo "Kibana Enrollment Token: $ENROLLMENT_TOKEN"

# Kibana Erişimi İçin Gerekli Bilgiler
echo "[*] Kibana erişimi sağlandı. Aşağıdaki bilgileri kullanarak Kibana'ya erişebilirsiniz."
echo "Kibana erişimi: https://<Sunucu_IP>:5601"
echo "Elastic kullanıcı adı: elastic"
echo "Elastic Parola: $KIBANA_PASSWORD"
echo "Kibana Enrollment Token: $ENROLLMENT_TOKEN"

echo "[*] ELK Stack (Elasticsearch, Kibana, Logstash) başarıyla kuruldu."