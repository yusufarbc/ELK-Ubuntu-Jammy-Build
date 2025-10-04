#!/bin/bash

# Proje için gerekli paketlerin kurulması
echo "Gerekli bağımlılıkları kuruyor..."
sudo apt-get update -y
sudo apt-get install -y \
  apt-transport-https \
  curl \
  wget \
  jq \
  gnupg \
  lsb-release \
  ca-certificates \
  software-properties-common \
  openjdk-11-jdk  # Elasticsearch ve Kibana için JDK gereklidir.

# Elasticsearch, Kibana ve Logstash için .deb paketlerini indirme
echo "Elasticsearch, Kibana ve Logstash paketleri indiriliyor..."

# Elasticsearch .deb paketi indiriliyor
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.19.4-amd64.deb

# Kibana .deb paketi indiriliyor
wget https://artifacts.elastic.co/downloads/kibana/kibana-8.19.4-amd64.deb

# Logstash .deb paketi indiriliyor
wget https://artifacts.elastic.co/downloads/logstash/logstash-8.19.4.deb

# Paketlerin kurulumu
echo "Paketler kuruluyor..."
sudo dpkg -i elasticsearch-8.19.4-amd64.deb
sudo dpkg -i kibana-8.19.4-amd64.deb
sudo dpkg -i logstash-8.19.4.deb

# Gerekli dizinlerin oluşturulması
echo "Logstash konfigürasyon dizini oluşturuluyor..."
sudo mkdir -p /etc/logstash/conf.d
sudo chown -R $USER:$USER /etc/logstash

# Sertifikaların otomatik oluşturulması
echo "Sertifikalar oluşturuluyor..."
sudo mkdir -p /etc/elasticsearch/certs
sudo openssl req -x509 -newkey rsa:4096 -keyout /etc/elasticsearch/certs/elasticsearch.key -out /etc/elasticsearch/certs/elasticsearch.crt -days 365 -nodes -subj "/CN=localhost"

# Kibana için SSL Sertifikası oluşturulması
sudo mkdir -p /etc/kibana/certs
sudo openssl req -x509 -newkey rsa:4096 -keyout /etc/kibana/certs/kibana.key -out /etc/kibana/certs/kibana.crt -days 365 -nodes -subj "/CN=localhost"

# Güçlü parolaların oluşturulması
echo "Güçlü parolalar oluşturuluyor..."
ELASTIC_PASSWORD=$(openssl rand -base64 16)
KIBANA_PASSWORD=$(openssl rand -base64 16)

# Elasticsearch konfigürasyon dosyasını düzenle
echo "Elasticsearch yapılandırması yapılıyor..."
sudo tee /etc/elasticsearch/elasticsearch.yml > /dev/null <<EOF
cluster.name: "elasticsearch-cluster"
node.name: "node-1"
network.host: 0.0.0.0
http.port: 9200
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: certs/elasticsearch.p12
xpack.security.transport.ssl.truststore.path: certs/elasticsearch.p12
EOF

# Kibana konfigürasyonu
echo "Kibana yapılandırması yapılıyor..."
sudo tee /etc/kibana/kibana.yml > /dev/null <<EOF
server.host: "0.0.0.0"
elasticsearch.hosts: ["https://localhost:9200"]
server.ssl.enabled: true
server.ssl.certificate: /etc/kibana/certs/kibana.crt
server.ssl.key: /etc/kibana/certs/kibana.key
xpack.security.enabled: true
xpack.encryptedSavedObjects.encryptionKey: "a_random_32_byte_string"
EOF

# Logstash için yapılandırma
echo "Logstash yapılandırması yapılıyor..."
sudo tee /etc/logstash/conf.d/fortigate.conf > /dev/null <<EOF
input {
  beats {
    port => 5044
  }
}

filter {
  grok {
    match => { "message" => "%{SYSLOGTIMESTAMP} %{SYSLOGHOST} %{DATA:fortigate_message}" }
  }
  kv {
    source => "fortigate_message"
  }
}

output {
  elasticsearch {
    hosts => ["https://localhost:9200"]
    index => "fortigate-logs-%{+YYYY.MM.dd}"
    user => "kibana_system"
    password => "${KIBANA_PASSWORD}"
    ssl => true
    cacert => "/etc/elasticsearch/certs/elasticsearch.crt"
  }
}
EOF

# Elasticsearch log dizini oluşturuluyor ve izinler ayarlanıyor
echo "Elasticsearch log dizini kontrol ediliyor..."
if [ ! -d "/usr/share/elasticsearch/logs" ]; then
    echo "Log dizini bulunamadı. Yeni log dizini oluşturuluyor..."
    sudo mkdir -p /usr/share/elasticsearch/logs
    sudo chown -R elasticsearch:elasticsearch /usr/share/elasticsearch/logs
else
    echo "Log dizini mevcut."
fi

# Elasticsearch ve Kibana servislerini başlat
echo "Servisler başlatılıyor..."

# Elasticsearch servisini başlat
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
if [[ $? -ne 0 ]]; then
  echo "Elasticsearch servisi başlatılamadı. Lütfen logları kontrol edin."
  exit 1
fi

# Kibana servisini başlat
sudo systemctl enable kibana
sudo systemctl start kibana
if [[ $? -ne 0 ]]; then
  echo "Kibana servisi başlatılamadı. Lütfen logları kontrol edin."
  exit 1
fi

# Logstash servisini başlat
sudo systemctl enable logstash
sudo systemctl start logstash
if [[ $? -ne 0 ]]; then
  echo "Logstash servisi başlatılamadı. Lütfen logları kontrol edin."
  exit 1
fi

# Kibana Enrollment Token alma
echo "Kibana Enrollment Token alınıyor..."
ENROLLMENT_TOKEN=$(sudo /usr/share/kibana/bin/kibana-enrollment-setup -i)
if [[ $? -ne 0 ]]; then
  echo "Kibana Enrollment Token alınamadı. Lütfen logları kontrol edin."
  exit 1
fi

# Kurulum ve yapılandırma bilgilerini yazdırma
echo "Kurulum tamamlandı!"
echo "Kibana erişimi: https://<Sunucu_IP>:5601"
echo "Elastic kullanıcı adı: elastic, Parola: ${ELASTIC_PASSWORD}"
echo "Kibana Enrollment Token: ${ENROLLMENT_TOKEN}"

echo "Kurulum başarılı. Kibana'ya giriş yapmak için yukarıdaki bilgileri kullanabilirsiniz."
