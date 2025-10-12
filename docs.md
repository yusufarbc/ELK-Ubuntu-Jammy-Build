# Ubuntu 22.04 Üzerinde Tek Sunucu Agentless SIEM Kurulum ve İşletim Kılavuzu
## Giriş

Bu kılavuz, Ubuntu 22.04 üzerinde tek sunucuda çalışan, agentless (Elastic Agent/Fleet yok) bir Elastic SIEM yığınının kurulum ve işletimini açıklar. Elasticsearch yalnızca localhost’ta TLS ile dinler; Kibana ve Logstash LAN’a açıktır. Amaç, tek komutla güvenli ve idempotent bir kurulum sağlamaktır.

## Bileşenler ve Mimari

- Elasticsearch (localhost:9200, TLS)
- Kibana (0.0.0.0:5601, HTTP)
- Logstash (Beats 5044/tcp, WEF 5045/tcp, Syslog 5514/udp+tcp, 5515/tcp, Kaspersky 5516/udp+tcp)

```
[Clients] -> [Logstash] -> [Elasticsearch]
Kullanıcı <-> Kibana <-> Elasticsearch
```

## Kurulum

```bash
git clone https://github.com/yusufarbc/ELK-Ubuntu-Jammy-Build.git
cd ELK-Ubuntu-Jammy-Build
chmod +x elk_setup_ubuntu_jammy.sh
sudo ./elk_setup_ubuntu_jammy.sh
```

Betik sonunda: Elastic parolası, Kibana enrollment token’ı ve Logstash keystore bilgisi (ES_PW) gösterilir.

## Doğrulama

```bash
systemctl status elasticsearch kibana logstash --no-pager
curl -s --cacert /etc/elasticsearch/certs/ca.crt https://localhost:9200 | jq .
sudo /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
```

## Log Kaynakları

- Windows WEF: Winlogbeat (WEC) → Logstash 5045/tcp
- Syslog: 5514/udp(+tcp), RFC5424: 5515/tcp
- Kaspersky: 5516/udp,tcp (JSON destekli)

## Data Streams ve ILM

- Data stream: `logs-<dataset>-default`
- ILM: `logs-90d`

## Sorun Giderme

- Kibana bağlanmıyor: ES sağlık, Kibana `elasticsearch.hosts` kontrol edin.
- Enrollment token üretimi: `elasticsearch-create-enrollment-token -s kibana`
- Logstash yazmıyor: `journalctl -u logstash -f`, keystore’da `ES_PW`.

## Temizlik

```bash
sudo systemctl stop logstash kibana elasticsearch || true
sudo rm -rf /etc/elasticsearch /etc/kibana /etc/logstash
sudo rm -rf /etc/systemd/system/elasticsearch.service.d
sudo rm -rf /var/log/elasticsearch /var/log/logstash
sudo rm -rf /var/lib/elasticsearch /var/lib/logstash
sudo rm -f /etc/default/logstash /etc/sysconfig/logstash
sudo systemctl daemon-reload
```

## Notlar

- Kibana LAN’da HTTP olarak kalır; ters proxy/SSL gerekmez.
- Bu kılavuz Türkçe tutulmuştur; uluslararası kullanım hedeflenmemiştir.
