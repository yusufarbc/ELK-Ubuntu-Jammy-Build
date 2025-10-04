#!/bin/bash
# Elastic SIEM On-Prem Kurulum Scripti (Stabil Sürüm - Ubuntu 22.04 LTS)
# Tek host, Docker'sız: Elasticsearch 8.x + Kibana + Logstash
# Bu sürüm, yaygın start hatalarını engellemek için ek tuning uygular.

set -euo pipefail
IFS=$'\n\t'
trap 'rc=$?; if [ $rc -ne 0 ]; then echo "[HATA] Betik $rc koduyla sonlandı" >&2; fi; exit $rc' EXIT

log() { printf "[%s] %s\n" "$1" "$2"; }
info(){ log "BILGI" "$1"; }
warn(){ log "UYARI" "$1"; }
err(){  log "HATA " "$1"; }

if [ "$(id -u)" != "0" ]; then
  echo "Lütfen bu scripti root olarak çalıştırın." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

info "APT güncelleniyor ve gerekli paketler kuruluyor..."
apt-get update -q
apt-get install -y -q apt-transport-https ca-certificates curl gnupg jq lsof

info "Elastic GPG ve APT deposu ekleniyor..."
install -d /usr/share/keyrings
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list
apt-get update -q

info "Elasticsearch, Kibana ve Logstash kuruluyor..."
apt-get install -y -q elasticsearch kibana logstash

info "Sistem tuning ve izinler uygulanıyor..."
echo "vm.max_map_count=262144" > /etc/sysctl.d/99-elasticsearch.conf
sysctl -w vm.max_map_count=262144 || true

cat > /etc/security/limits.d/99-elasticsearch.conf <<'LIMITS'
elasticsearch soft nofile 65536
elasticsearch hard nofile 65536
elasticsearch soft memlock unlimited
elasticsearch hard memlock unlimited
elasticsearch soft nproc 4096
elasticsearch hard nproc 4096
LIMITS

HEAP_MB=1024
if [ -r /proc/meminfo ]; then
  MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo || echo 0)
  if [ "$MEM_KB" -gt 0 ]; then
    MEM_MB=$((MEM_KB/1024))
    HEAP_MB=$((MEM_MB/2)); [ "$HEAP_MB" -gt 32768 ] && HEAP_MB=32768
  fi
fi
install -d /etc/systemd/system/elasticsearch.service.d
cat > /etc/systemd/system/elasticsearch.service.d/override.conf <<EOF
[Service]
Environment="ES_JAVA_OPTS=-Xms${HEAP_MB}m -Xmx${HEAP_MB}m"
LimitMEMLOCK=infinity
LimitNOFILE=65536
LimitNPROC=4096
TimeoutStartSec=900
EOF

ES_DATA="/var/lib/elasticsearch"
ES_LOGDIR="/var/log/elasticsearch"
install -d "$ES_DATA" "$ES_LOGDIR"
chown -R elasticsearch:elasticsearch "$ES_DATA" "$ES_LOGDIR"
chmod -R 0750 "$ES_DATA" "$ES_LOGDIR"

ES_YML="/etc/elasticsearch/elasticsearch.yml"
info "Elasticsearch yapılandırılıyor..."
if grep -Eq '^\s*#?\s*network\.host:' "$ES_YML"; then
  sed -ri 's|^\s*#?\s*network\.host:.*|network.host: 127.0.0.1|' "$ES_YML"
else
  echo "network.host: 127.0.0.1" >> "$ES_YML"
fi
grep -q '^discovery.type' "$ES_YML" || echo "discovery.type: single-node" >> "$ES_YML"
if grep -Eq '^\s*#?\s*bootstrap\.memory_lock:' "$ES_YML"; then
  sed -ri 's|^\s*#?\s*bootstrap\.memory_lock:.*|bootstrap.memory_lock: true|' "$ES_YML"
else
  echo "bootstrap.memory_lock: true" >> "$ES_YML"
fi

systemctl daemon-reload
systemctl enable elasticsearch

info "Elasticsearch başlatılıyor..."
if ! systemctl start elasticsearch; then
  err "Elasticsearch başlatılamadı. Son log:"
  journalctl -u elasticsearch -b --no-pager | tail -n 100 >&2 || true
  [ -f /var/log/elasticsearch/elasticsearch.log ] && tail -n 100 /var/log/elasticsearch/elasticsearch.log >&2 || true
  exit 1
fi

info "Elasticsearch sağlıklanması bekleniyor..."
for i in {1..40}; do
  if curl -sk https://localhost:9200 >/dev/null 2>&1; then break; fi
  sleep 3
done

info "Elastic 'elastic' kullanıcısı için parola oluşturuluyor..."
ELASTIC_PW="$(yes | /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b 2>/dev/null | awk '/New value:/ {print $NF}')"
if [ -z "${ELASTIC_PW}" ]; then
  err "Parola üretilemedi. Elasticsearch loglarını kontrol edin."
  exit 1
fi
echo "$ELASTIC_PW" > /root/.elastic_pw && chmod 600 /root/.elastic_pw
info "Yeni 'elastic' şifresi /root/.elastic_pw dosyasına kaydedildi."

info "Kibana için enrollment token alınıyor..."
KIBANA_TOKEN="$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana || true)"
[ -z "$KIBANA_TOKEN" ] && warn "Kibana enrollment token şu an alınamadı."

KB_YML="/etc/kibana/kibana.yml"
info "Kibana yapılandırılıyor..."
if grep -Eq '^\s*#?\s*server\.host:' "$KB_YML"; then
  sed -ri 's|^\s*#?\s*server\.host:.*|server.host: "0.0.0.0"|' "$KB_YML"
else
  echo 'server.host: "0.0.0.0"' >> "$KB_YML"
fi

systemctl enable kibana
sleep 5
systemctl start kibana || {
  err "Kibana başlatılamadı. Son log:"
  journalctl -u kibana -b --no-pager | tail -n 120 >&2 || true
  exit 1
}

info "Logstash pipeline yazılıyor..."
cat > /etc/logstash/conf.d/00-siem.conf <<'LSCONF'
input {
  beats { port => 5044 }
  udp   { port => 5514 type => "syslog" }
  tcp   { port => 5514 type => "syslog" }
}
filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "<%{NUMBER:priority}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{HOSTNAME:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
    }
    date {
      match => [ "syslog_timestamp", "MMM dd HH:mm:ss", "MMM  d HH:mm:ss" ]
    }
  }
}
output {
  elasticsearch {
    hosts    => ["https://localhost:9200"]
    index    => "syslog-%{+YYYY.MM.dd}"
    user     => "elastic"
    password => "__ELASTIC_PW__"
    ssl      => true
    cacert   => "/etc/elasticsearch/certs/http_ca.crt"
  }
}
LSCONF

sed -i "s/__ELASTIC_PW__/$ELASTIC_PW/" /etc/logstash/conf.d/00-siem.conf

systemctl enable logstash
/usr/share/logstash/bin/logstash --path.settings /etc/logstash -t >/dev/null 2>&1 || {
  err "Logstash config test başarısız!"; /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t || true; exit 1; }
systemctl start logstash || { err "Logstash başlatılamadı."; journalctl -u logstash -b --no-pager | tail -n 120 >&2 || true; exit 1; }

echo
echo "=== KURULUM TAMAMLANDI ==="
echo "Kibana: https://<SunucuIP>:5601"
echo "Kullanıcı: elastic"
echo "Parola (root erişim): /root/.elastic_pw"
[ -n "$KIBANA_TOKEN" ] && echo "Kibana Enrollment Token: $KIBANA_TOKEN"
echo "Elasticsearch'e dış erişim açmak için /etc/elasticsearch/elasticsearch.yml içinde"
echo "  network.host: 0.0.0.0  yapın ve 'sudo systemctl restart elasticsearch' uygulayın."
