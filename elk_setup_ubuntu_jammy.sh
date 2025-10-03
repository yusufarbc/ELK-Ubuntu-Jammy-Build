#!/bin/bash
# Elastic SIEM On-Prem Kurulum Scripti (Basitleştirilmiş & Düzeltilmiş)
# Hedef: Ubuntu 22.04 LTS tek host, Docker'sız; Elasticsearch + Kibana + Logstash
# Notlar:
# - İlk açılışta Elasticsearch'ü ayağa kaldırıp şifre/token alıyoruz.
# - Syslog için 5514 (TCP/UDP) kullanıyoruz (privileged port gerektirmez).
# - APT işlemleri noninteractive.

set -euo pipefail
IFS=$'\n\t'

if [ "$(id -u)" != "0" ]; then
  echo "Lütfen bu scripti root olarak çalıştırın." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

echo "[*] APT güncelleniyor ve gerekli paketler kuruluyor..."
apt-get update -q
apt-get install -y -q apt-transport-https ca-certificates curl gnupg jq

echo "[*] Elastic GPG anahtarı ve depo ekleniyor..."
install -d /usr/share/keyrings
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list
apt-get update -q

echo "[*] Elasticsearch, Kibana ve Logstash kuruluyor..."
apt-get install -y -q elasticsearch kibana logstash

# ---------------- Elasticsearch ----------------
echo "[*] Elasticsearch yapılandırılıyor..."
ES_YML="/etc/elasticsearch/elasticsearch.yml"

# Erişimi güvenli tutmak için ilk etapta localhost'a bağla. Dış erişim isterseniz sonradan 0.0.0.0 yapabilirsiniz.
if grep -Eq '^\s*#?\s*network\.host:' "$ES_YML"; then
  sed -ri 's|^\s*#?\s*network\.host:.*|network.host: 127.0.0.1|' "$ES_YML"
else
  echo "network.host: 127.0.0.1" >> "$ES_YML"
fi
grep -q '^discovery.type' "$ES_YML" || echo "discovery.type: single-node" >> "$ES_YML"

systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch

# ES health bekleme döngüsü
echo "[*] Elasticsearch sağlıklı hale gelmesi bekleniyor..."
for i in {1..30}; do
  if curl -sk https://localhost:9200 >/dev/null 2>&1; then
    break
  fi
  sleep 3
done

echo "[*] Elastic 'elastic' kullanıcısı için parola oluşturuluyor..."
ELASTIC_PW="$(yes | /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b 2>/dev/null | awk '/New value:/ {print $NF}')"
if [ -z "$ELASTIC_PW" ]; then
  echo "[HATA] Parola üretilemedi. Elasticsearch loglarını kontrol edin." >&2
  exit 1
fi
echo "$ELASTIC_PW" > /root/.elastic_pw
chmod 600 /root/.elastic_pw
echo "[*] Yeni 'elastic' şifresi /root/.elastic_pw dosyasına kaydedildi."

echo "[*] Kibana için enrollment token alınıyor..."
KIBANA_TOKEN="$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)"
if [ -z "$KIBANA_TOKEN" ]; then
  echo "[UYARI] Kibana enrollment token alınamadı. ES loglarını kontrol edin." >&2
fi

# ---------------- Kibana ----------------
echo "[*] Kibana yapılandırılıyor..."
KB_YML="/etc/kibana/kibana.yml"
if grep -Eq '^\s*#?\s*server\.host:' "$KB_YML"; then
  sed -ri 's|^\s*#?\s*server\.host:.*|server.host: "0.0.0.0"|' "$KB_YML"
else
  echo 'server.host: "0.0.0.0"' >> "$KB_YML"
fi

systemctl enable kibana
# Elasticsearch tam otursun diye kısa bekleme
sleep 10
systemctl start kibana

# ---------------- Logstash ----------------
echo "[*] Logstash pipeline oluşturuluyor..."
cat > /etc/logstash/conf.d/00-siem.conf <<'LSCONF'
input {
  beats {
    port => 5044
  }
  udp {
    port => 5514
    type => "syslog"
  }
  tcp {
    port => 5514
    type => "syslog"
  }
}
filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "<%{NUMBER:priority}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{HOSTNAME:syslog_hostname} %{DATA:syslog_program}(?:\\[%{POSINT:syslog_pid}\\])?: %{GREEDYDATA:syslog_message}" }
    }
    date {
      match => [ "syslog_timestamp", "MMM dd HH:mm:ss", "MMM  d HH:mm:ss" ]
    }
  }
}
output {
  elasticsearch {
    hosts => ["https://localhost:9200"]
    index => "syslog-%{+YYYY.MM.dd}"
    user => "elastic"
    password => "__ELASTIC_PW__"
    ssl => true
    cacert => "/etc/elasticsearch/certs/http_ca.crt"
  }
}
LSCONF

# Şifreyi pipeline'a enjekte et (güvenli kaçış gerekmez; basit örnek)
sed -i "s/__ELASTIC_PW__/$ELASTIC_PW/" /etc/logstash/conf.d/00-siem.conf

systemctl enable logstash
systemctl start logstash

echo
echo "=== KURULUM TAMAMLANDI ==="
echo "Kibana erişimi: https://<SunucuIP>:5601"
echo "Elastic kullanıcı adı: elastic"
echo "Elastic parola (root ile): /root/.elastic_pw"
[ -n "$KIBANA_TOKEN" ] && echo "Kibana Enrollment Token: $KIBANA_TOKEN"
echo "Not: Elasticsearch'e dış erişim isterseniz /etc/elasticsearch/elasticsearch.yml içinde"
echo "     network.host: 0.0.0.0 yapıp 'sudo systemctl restart elasticsearch' uygulayın."
