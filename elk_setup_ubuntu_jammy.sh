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
CERT_DIR="/etc/elasticsearch/certs"

# Sertifika dizini kontrol edilip oluşturuluyor
if [ ! -d "$CERT_DIR" ]; then
  echo "[*] Sertifika dizini yok, oluşturuluyor..."
  sudo mkdir -p $CERT_DIR
fi

# Sertifika dosyasını kontrol et, varsa sil
if [ -f $CERT_DIR/elastic-stack-ca.zip ]; then
  echo "[*] Sertifika dosyası mevcut, siliniyor..."
  sudo rm -f $CERT_DIR/elastic-stack-ca.zip
fi

# Sertifikaların oluşturulması (parolasız)
echo "[*] Sertifikalar oluşturuluyor..."
sudo /usr/share/elasticsearch/bin/elasticsearch-certutil ca --pem --no-password --out $CERT_DIR/elastic-stack-ca.zip
sudo /usr/share/elasticsearch/bin/elasticsearch-certutil cert --pem --ca $CERT_DIR/elastic-stack-ca.zip --no-password --out $CERT_DIR/elastic-certificates.zip

# Elasticsearch için SSL/TLS yapılandırması
echo "[*] Elasticsearch için SSL/TLS yapılandırması yapılıyor..."
sudo bash -c "echo 'xpack.security.transport.ssl.enabled: true' >> /etc/elasticsearch/elasticsearch.yml"
sudo bash -c "echo 'xpack.security.http.ssl.enabled: true' >> /etc/elasticsearch/elasticsearch.yml"
sudo bash -c "echo 'xpack.security.http.ssl.keystore.path: /etc/elasticsearch/certs/elastic-certificates.p12' >> /etc/elasticsearch/elasticsearch.yml"
sudo bash -c "echo 'xpack.security.http.ssl.truststore.path: /etc/elasticsearch/certs/elastic-certificates.p12' >> /etc/elasticsearch/elasticsearch.yml"

# Kibana için enrollment token alınması
echo "[*] Kibana için enrollment token alınıyor..."
KIBANA_TOKEN=$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)

echo "Kibana Enrollment Token: $KIBANA_TOKEN"

# Kibana yapılandırması
echo "[*] Kibana yapılandırması yapılıyor..."
sudo bash -c "echo 'elasticsearch.username: \"elastic\"' >> /etc/kibana/kibana.yml"
sudo bash -c "echo 'elasticsearch.password: \"$ELASTIC_PASSWORD\"' >> /etc/kibana/kibana.yml"
sudo bash -c "echo 'server.ssl.enabled: true' >> /etc/kibana/kibana.yml"
sudo bash -c "echo 'server.ssl.certificate: /etc/elasticsearch/certs/elastic-certificates.crt' >> /etc/kibana/kibana.yml"
sudo bash -c "echo 'server.ssl.key: /etc/elasticsearch/certs/elastic-certificates.key' >> /etc/kibana/kibana.yml"
sudo bash -c "echo 'elasticsearch.ssl.certificateAuthorities: [\"/etc/elasticsearch/certs/http_ca.crt\"]' >> /etc/kibana/kibana.yml"
sudo bash -c "echo 'xpack.security.enabled: true' >> /etc/kibana/kibana.yml"
sudo bash -c "echo 'xpack.security.enrollmentToken: \"$KIBANA_TOKEN\"' >> /etc/kibana/kibana.yml"

# Logstash kurulumu
echo "[*] Logstash kuruluyor..."
sudo apt-get install -y logstash

# Logstash pipeline yapılandırması
echo "[*] Logstash pipeline yapılandırması yapılıyor..."
cat <<'LSCONF' | sudo tee /etc/logstash/conf.d/logstash.conf
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
    password => "$KIBANA_PASSWORD"
    ssl => true
    cacert => "/etc/elasticsearch/certs/http_ca.crt"
  }
}
LSCONF

# Logstash servisinin etkinleştirilmesi
echo "[*] Logstash servisleri etkinleştiriliyor..."
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