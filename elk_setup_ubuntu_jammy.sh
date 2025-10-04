#!/bin/bash

# Elastic Stack (Elasticsearch, Kibana, Logstash) kurulumu ve yapılandırması

# Sistem gereksinimlerini kontrol et
if [ "$(id -u)" != "0" ]; then
  echo "Lütfen bu scripti root olarak çalıştırın." >&2
  exit 1
fi

# Genel değişkenler
ELASTIC_VERSION="8.x"
CERTS_DIR="/etc/elasticsearch/certs"
KIBANA_PORT="5601"
ELASTIC_PASSWORD="$1"  # Elastic kullanıcısının şifresi

# Paketleri güncelle ve gerekli bağımlılıkları yükle
echo "[*] APT güncelleniyor ve gerekli paketler kuruluyor..."
apt update && apt install -y apt-transport-https curl gnupg jq nginx

# Elastic APT deposunu ekle
echo "[*] Elastic GPG anahtarı ekleniyor..."
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/$ELASTIC_VERSION/apt stable main" > /etc/apt/sources.list.d/elastic-$ELASTIC_VERSION.list
apt update

# Elasticsearch kurulumu
echo "[*] Elasticsearch kuruluyor..."
DEBIAN_FRONTEND=noninteractive apt install -y elasticsearch

# Elasticsearch ayarlarını yap (SSL/TLS ile güvenli bağlantılar)
echo "[*] Elasticsearch yapılandırılıyor..."
mkdir -p $CERTS_DIR
# Sertifikalarınızı oluşturun veya mevcut sertifikaları kullanın.
# Sertifikaları /etc/elasticsearch/certs/ dizinine yerleştirin.

# SSL yapılandırması
cat <<EOL > /etc/elasticsearch/elasticsearch.yml
xpack.security.enabled: true
xpack.security.enrollment.enabled: true

# HTTP API SSL yapılandırması
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: $CERTS_DIR/http.p12

# Transport SSL yapılandırması
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: $CERTS_DIR/transport.p12
xpack.security.transport.ssl.truststore.path: $CERTS_DIR/transport.p12

# İlk master node yapılandırması
cluster.initial_master_nodes: ["localhost"]

# Elasticsearch'i başlat ve aktif hale getir
systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch

# Kibana kurulumu
echo "[*] Kibana kuruluyor..."
DEBIAN_FRONTEND=noninteractive apt install -y kibana

# Kibana yapılandırması
echo "[*] Kibana yapılandırılıyor..."
cat <<EOL > /etc/kibana/kibana.yml
server.host: "0.0.0.0"
elasticsearch.hosts: ["https://localhost:9200"]
elasticsearch.username: "elastic"
elasticsearch.password: "$ELASTIC_PASSWORD"  # Elastic 'elastic' kullanıcısı için şifrenizi buraya girin
elasticsearch.ssl.verificationMode: full
elasticsearch.ssl.certificateAuthorities: ["/etc/elasticsearch/certs/http_ca.crt"]
server.ssl.enabled: true
server.ssl.certificate: "/etc/elasticsearch/certs/kibana.crt"
server.ssl.key: "/etc/elasticsearch/certs/kibana.key"
EOL

# Kibana servisini başlat
systemctl enable kibana
systemctl start kibana

# Logstash kurulumu
echo "[*] Logstash kuruluyor..."
DEBIAN_FRONTEND=noninteractive apt install -y logstash

# Logstash yapılandırması (SSL ile güvenli bağlantı)
echo "[*] Logstash yapılandırması yapılıyor..."
cat <<EOL > /etc/logstash/conf.d/00-siem.conf
input {
  beats {
    port => 5044
  }
}

output {
  elasticsearch {
    hosts => ["https://localhost:9200"]
    index => "logstash-%{+YYYY.MM.dd}"
    user => "elastic"
    password => "$ELASTIC_PASSWORD"  # Elastic 'elastic' kullanıcısı için şifrenizi buraya girin
    ssl => true
    cacert => "/etc/elasticsearch/certs/http_ca.crt"
  }
}
EOL

# Logstash servisini başlat
systemctl enable logstash
systemctl start logstash

# Nginx Ters Proxy yapılandırması
echo "[*] Nginx ters proxy yapılandırması yapılıyor..."
cat <<EOL > /etc/nginx/sites-available/kibana
server {
    listen 443 ssl;
    server_name kibana.local;

    ssl_certificate /etc/elasticsearch/certs/kibana.crt;
    ssl_certificate_key /etc/elasticsearch/certs/kibana.key;

    location / {
        proxy_pass https://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOL

# Nginx'e Kibana konfigürasyonunu aktif et
ln -s /etc/nginx/sites-available/kibana /etc/nginx/sites-enabled/
systemctl restart nginx

# Kibana için Enrollment Token alınıyor
echo "[*] Kibana için enrollment token alınıyor..."
KIBANA_TOKEN=$(curl -u elastic:$ELASTIC_PASSWORD -X POST "https://localhost:9200/_security/enroll/kibana" --insecure)

if [ -n "$KIBANA_TOKEN" ]; then
  export KIBANA_ENROLLMENT_TOKEN="$KIBANA_TOKEN"
  echo "[*] Kibana Enrollment Token alındı ve ENV değişkenine atandı."
else
  echo "[HATA] Kibana Enrollment Token alınamadı!" >&2
  exit 1
fi

# Son bilgilendirme
echo "[*] Kurulum tamamlandı."
echo "Elastic Stack (Elasticsearch, Kibana, Logstash) başarıyla kuruldu."
echo "Kibana erişimi: https://<sunucu_adresi>:5601"
echo "Elastic kullanıcı adı: elastic"
echo "NOT: Kibana ilk açılışta Enrollment Token isteyecektir, yukarıda üretilen token'ı kullanınız."

# Kibana Enrollment Token'ı ekrana basma
echo "[*] Kibana Enrollment Token: $KIBANA_ENROLLMENT_TOKEN"

# Nginx ve Kibana loglarını izleme komutları (gerekirse)
echo "[*] Nginx loglarını izleyebilirsiniz: sudo tail -f /var/log/nginx/error.log"
echo "[*] Kibana loglarını izleyebilirsiniz: sudo journalctl -u kibana.service -f"
