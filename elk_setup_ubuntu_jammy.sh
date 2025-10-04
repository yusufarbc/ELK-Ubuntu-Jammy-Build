#!/bin/bash
set -e

# Değişkenler
ES_VERSION="9.0.0"
KIBANA_VERSION="9.0.0"
LOGSTASH_VERSION="9.0.0"
STACK_VERSION="9.x"
REPO_URL="https://artifacts.elastic.co/packages/$STACK_VERSION/apt"

# Gerekli paketlerin kurulumu
echo "[*] Gerekli bağımlılıklar kuruluyor..."
sudo apt-get update && sudo apt-get install -y \
  apt-transport-https \
  curl \
  gnupg2 \
  lsb-release \
  jq \
  unzip \
  sudo

# Elasticsearch GPG anahtarının eklenmesi
echo "[*] Elasticsearch GPG anahtarı ekleniyor..."
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Elasticsearch APT deposunun eklenmesi
echo "[*] Elasticsearch APT deposu ekleniyor..."
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] $REPO_URL stable main" | sudo tee /etc/apt/sources.list.d/elastic-9.x.list

# Paket listelerinin güncellenmesi
echo "[*] Paket listesi güncelleniyor..."
sudo apt-get update

# Elasticsearch, Kibana ve Logstash paketlerinin kurulumu
echo "[*] Elasticsearch kuruluyor..."
sudo apt-get install -y elasticsearch=$ES_VERSION
echo "[*] Kibana kuruluyor..."
sudo apt-get install -y kibana=$KIBANA_VERSION
echo "[*] Logstash kuruluyor..."
sudo apt-get install -y logstash=$LOGSTASH_VERSION

# Elasticsearch ve Kibana servislerinin etkinleştirilmesi
echo "[*] Elasticsearch ve Kibana servisleri etkinleştiriliyor..."
sudo systemctl enable elasticsearch.service
sudo systemctl enable kibana.service

# Elasticsearch ve Kibana servislerinin başlatılması
echo "[*] Elasticsearch ve Kibana servisleri başlatılıyor..."
sudo systemctl start elasticsearch.service
sudo systemctl start kibana.service

# Elasticsearch için SSL/TLS sertifikası oluşturulması
echo "[*] Elasticsearch için SSL/TLS sertifikası oluşturuluyor..."
sudo /usr/share/elasticsearch/bin/elasticsearch-certutil cert --pem --in /etc/elasticsearch/elasticsearch.yml --out /etc/elasticsearch/certs/elastic-certificates.p12

# Sertifikaların uygun dizine kopyalanması
echo "[*] Sertifikalar uygun dizine kopyalanıyor..."
sudo cp /etc/elasticsearch/certs/elastic-certificates.p12 /etc/elasticsearch/certs/elastic-certificates.p12

# Kibana için Enrollment Token alınması
echo "[*] Kibana için Enrollment Token alınıyor..."
ENROLLMENT_TOKEN=$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)
echo "Kibana Enrollment Token: $ENROLLMENT_TOKEN"

# Logstash pipeline dosyasının oluşturulması
echo "[*] Logstash pipeline dosyası oluşturuluyor..."
sudo mkdir -p /etc/logstash/conf.d
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
    hosts => ['https://localhost:9200']
    index => 'fortigate-logs-%{+YYYY.MM.dd}'
    user => 'elastic'
    password => '<Elastic_Password>'
    ssl => true
    cacert => '/etc/elasticsearch/certs/http_ca.crt'
  }
}
" | sudo tee /etc/logstash/conf.d/logstash.conf

# Logstash servisinin etkinleştirilmesi
echo "[*] Logstash servisi etkinleştiriliyor..."
sudo systemctl enable logstash.service

# Logstash servisinin başlatılması
echo "[*] Logstash servisi başlatılıyor..."
sudo systemctl start logstash.service

# Kibana erişim bilgileri
KIBANA_URL="https://localhost:5601"
KIBANA_USER="elastic"
KIBANA_PASSWORD="<Elastic_Password>"

# Sonuçların yazdırılması
echo "[*] Kurulum tamamlandı."
echo "Kibana erişimi: $KIBANA_URL"
echo "Elastic kullanıcı adı: $KIBANA_USER, Parola: $KIBANA_PASSWORD"
echo "Kibana Enrollment Token: $ENROLLMENT_TOKEN"