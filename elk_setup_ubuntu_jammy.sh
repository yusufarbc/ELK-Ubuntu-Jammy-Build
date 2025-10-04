#!/bin/bash

# ELK Stack kurulumuna başlıyoruz
echo "ELK Stack kurulumuna başlıyoruz..."

# Gerekli bağımlılıkları kurma
echo "Bağımlılıklar kuruluyor..."
sudo apt-get update -y
sudo apt-get install -y \
  apt-transport-https \
  curl \
  wget \
  jq \
  gnupg \
  lsb-release \
  ca-certificates \
  openjdk-11-jdk \
  software-properties-common

# Elastic'in resmi GPG anahtarını ekleyip repo adresini ekliyoruz
echo "Elastic'in resmi repo ve GPG anahtarları ekleniyor..."
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo tee /etc/apt/trusted.gpg.d/elasticsearch.asc
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-8.x.list

# Paket listelerini güncelleyip Elastic paketlerini kuruyoruz
echo "Elastic paketleri kuruluyor..."
sudo apt-get update -y
sudo apt-get install -y elasticsearch kibana logstash

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

# Kibana konfigürasyonu yapma
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

# Logstash için yapılandırma dosyasını oluşturma
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

# Sertifikaların oluşturulması
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

# Elasticsearch veri dizini ve log dizini için gerekli izinlerin verilmesi
echo "Elasticsearch veri dizini ve log dizini izinleri kontrol ediliyor..."

# Elasticsearch veri dizini ve log dizini kontrolü
for dir in "/usr/share/elasticsearch/data" "/usr/share/elasticsearch/logs"; do
    if [ ! -d "$dir" ]; then
        echo "Dizin bulunamadı: $dir. Yeni dizin oluşturuluyor..."
        sudo mkdir -p $dir
    fi
    echo "İzinler ayarlanıyor: $dir"
    sudo chown -R elasticsearch:elasticsearch $dir
    sudo chmod -R 755 $dir
done

# Elasticsearch ve Kibana servislerini başlatıyoruz
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