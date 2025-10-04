#!/bin/bash

set -e

# 1. GPG Anahtarını ve Elasticsearch Repo Kaynağını Ekleyelim
echo "[*] Elastic GPG anahtarı ekleniyor..."
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo tee /usr/share/keyrings/elastic-archive-keyring.gpg

echo "[*] Elastic APT deposu ekleniyor..."
echo "deb [signed-by=/usr/share/keyrings/elastic-archive-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

echo "[*] Paket listesi güncelleniyor..."
sudo apt-get update -y

# 2. Elasticsearch Kurulumu
echo "[*] Elasticsearch kuruluyor..."
sudo apt-get install -y elasticsearch

# 3. Elasticsearch Yapılandırma
echo "[*] Elasticsearch yapılandırması yapılıyor..."
sudo sed -i 's|#network.host: .*|network.host: 0.0.0.0|' /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's|#http.port: 9200|http.port: 9200|' /etc/elasticsearch/elasticsearch.yml
sudo sed -i 's|#discovery.type: .*|discovery.type: single-node|' /etc/elasticsearch/elasticsearch.yml

# 4. Elasticsearch Servisini Başlat
echo "[*] Elasticsearch servisi başlatılıyor..."
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# 5. Elastic Kullanıcı Şifresi Sıfırlanması
echo "[*] Elastic kullanıcı şifresi sıfırlanıyor..."
ELASTIC_PW="$(sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b)"
echo "Yeni 'elastic' şifresi: $ELASTIC_PW"

# 6. Kibana için Enrollment Token Alınması
echo "[*] Kibana için enrollment token alınıyor..."
KIBANA_TOKEN="$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)"
echo "Kibana Enrollment Token: $KIBANA_TOKEN"

# 7. Kibana Kurulumu
echo "[*] Kibana kuruluyor..."
sudo apt-get install -y kibana

# 8. Kibana Yapılandırması
echo "[*] Kibana yapılandırması yapılıyor..."
sudo sed -i 's|#server.host: .*|server.host: "0.0.0.0"|' /etc/kibana/kibana.yml
sudo sed -i "s|#elasticsearch.username: .*|elasticsearch.username: \"elastic\"|" /etc/kibana/kibana.yml
sudo sed -i "s|#elasticsearch.password: .*|elasticsearch.password: \"$ELASTIC_PW\"|" /etc/kibana/kibana.yml

# 9. Kibana Servisini Başlat
echo "[*] Kibana servisi başlatılıyor..."
sudo systemctl enable kibana
sudo systemctl start kibana

# 10. Logstash Kurulumu
echo "[*] Logstash kuruluyor..."
sudo apt-get install -y logstash

# 11. Logstash Pipeline Yapılandırması
echo "[*] Logstash pipeline yapılandırması yapılıyor..."
cat <<EOF | sudo tee /etc/logstash/conf.d/logstash.conf
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
    password => "$ELASTIC_PW"
    ssl => true
    cacert => "/etc/elasticsearch/certs/http_ca.crt"
  }
}
EOF

# 12. Logstash Servisini Başlat
echo "[*] Logstash servisi başlatılıyor..."
sudo systemctl enable logstash
sudo systemctl start logstash

# 13. Sonuçları Kontrol Etme
echo "[*] Kurulum tamamlandı. ELK Stack (Elasticsearch, Kibana, Logstash) başarıyla kuruldu."

echo "Kibana erişimi: https://<Sunucu_IP>:5601"
echo "Elastic kullanıcı adı: elastic, Parola: $ELASTIC_PW"
echo "Kibana Enrollment Token: $KIBANA_TOKEN"