# Konfigürasyon Rehberi — Agentless Elastic SIEM (Rocky Linux + Docker) — Orta Ölçek (≈100 GB/gün)

Bu doküman, verdiğiniz gereksinimler (Rocky Linux üzerinde Docker kullanarak, ajan kullanılmayan mimari, günlük ≈100 GB log) doğrultusunda hazırlanan ayrıntılı konfigürasyon notlarını içerir. Amaç: hızlıca uygulayabileceğiniz, üretime yönelik öneriler ve hazır snippet'ler sunmaktır.

Not: Bu rehber "örnek / öneri" niteliğindedir. Parolalar, IP'ler ve sertifikalar ortamınıza göre özelleştirilmelidir.

## İçerik
- Özet ve mimari bileşenleri
- Sistem / kernel / JVM tuning
- Docker & Docker Compose temel ayarları (kaynak sınırları, volume mapping)
- Elasticsearch (container) için production konfigürasyon snippetleri
- Logstash pipeline örnekleri (WEF/Winlogbeat, Syslog, Kaspersky)
- Winlogbeat (WEC kolektör) ve rsyslog örnekleri
- ILM ve index template örnekleri
- KQL örnek kurallar (MITRE eşlemeli)
- Snapshot, monitoring ve operasyonel ipuçları

---

## 1. Kısa Mimari Özeti
- Host: Rocky Linux (bare-metal veya VM). Docker Engine + Docker Compose kurulmuş.
- Bileşenler (her biri docker container): Elasticsearch (1 veya daha fazla container), Logstash, Kibana.
- Log toplama: Windows → WEF/WEC → Winlogbeat (sadece WEC üzerine kurulu) → Logstash(5044); Linux/Firewall → rsyslog → Logstash(UDP/TCP 514 veya 5514); Kaspersky → KSC → Syslog (TCP 1514) → Logstash.
- Depolama: NVMe SSD (Elasticsearch data için özel partition/volume). Logstash için ayrı küçük SSD/volume önerilir.

## 2. Sistem ve Kernel Tuning (Rocky Linux host)
Aşağıdaki ayarları host seviyesinde kalıcı olarak uygulayın:

```bash
# vm.max_map_count (Elasticsearch için)
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf

# swap kapatma (veya düşük swappiness)
sudo swapoff -a
sudo sed -i 's/^.*swap.*/# swap disabled/' /etc/fstab || true

# file descriptor limitleri (elasticsearch user için)
echo -e "elasticsearch soft nofile 65536\nelasticsearch hard nofile 65536" | sudo tee /etc/security/limits.d/90-elasticsearch.conf

# ulimit / systemd ile çalıştıracaksanız unit içine ekleyin (ör: LimitNOFILE=65536)
```

Ayrıca Docker host üzerinde yeterli IOPS/CPU rezerve edin; konteyner CPU ve bellek pinlemesi yapılacaktır.

## 3. Docker & Compose Temel Öneriler
- Docker versiyonu: son stabil (Engine + Compose CLI). Docker daemon için `default-ulimits` veya `--default-ulimit` ile nofile değeri yükseltilebilir.
- Volume mapping: Elasticsearch veri dizinlerini doğrudan host mount haline getirin (bind mount) — overlayfs gecikmelerine dikkat.

docker-compose.yml'ye örnek kaynak kısıtlaması (özet):

```yaml
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - "ES_JAVA_OPTS=-Xms32g -Xmx32g"
      - discovery.type=single-node
    volumes:
      - /mnt/nvme/elasticsearch/data:/usr/share/elasticsearch/data
    deploy:
      resources:
        limits:
          memory: 64G
          cpus: '12.0'
    ulimits:
      nofile:
        soft: 65536
        hard: 65536

  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.0
    environment:
      - "LS_JAVA_OPTS=-Xms4g -Xmx4g"
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline
    deploy:
      resources:
        limits:
          memory: 8G
          cpus: '4.0'

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    environment:
      - ELASTICSEARCH_HOSTS=https://elasticsearch:9200
    deploy:
      resources:
        limits:
          memory: 4G
          cpus: '2.0'
```

Notlar:
- `deploy:` altındaki ayarlar Docker Swarm ile uyumludur; tek-node Docker Compose'da `mem_limit` ve `cpus` kullanabilirsiniz.
- Mutlaka host `vm.max_map_count` değeri set edilmiş olmalı.

## 4. Elasticsearch Konfigürasyonu (Container içinde -> `elasticsearch.yml` snippet)
Minimal üretim ayarları (örnek):

```yaml
cluster.name: siem-cluster
node.name: es-node-1
network.host: 0.0.0.0
http.port: 9200
transport.port: 9300
xpack.security.enabled: true
xpack.monitoring.collection.enabled: true
path.data: /usr/share/elasticsearch/data
path.logs: /usr/share/elasticsearch/logs
bootstrap.memory_lock: true
```

JVM (heap) ayarı:
- ES_JAVA_OPTS veya docker compose içinde ES_JAVA_OPTS="-Xms32g -Xmx32g"
- JVM heap size 32g üzeri olmayacak (G1GC limits), toplam RAM'in yarısı kadar olmalı.

## 5. Logstash Pipeline Örnekleri
Pipeline'ları `./logstash/pipeline/` içine yerleştirin (dosya isimleri: `10-inputs.conf`, `20-filters.conf`, `30-outputs.conf`). Örnekler aşağıdadır.

### 5.1 Inputs (WEF/Winlogbeat, Syslog, KES)
```conf
input {
  beats { port => 5044 }           # Winlogbeat -> WEC
  tcp { port => 5514 type => "syslog" codec => line { charset => "UTF-8" } }
  udp { port => 5514 type => "syslog" codec => plain { charset => "UTF-8" } }
}
```
**Not:** 514 portu host'ta root yetkisi gerektirir; Docker kullanıyorsanız host port yönlendirmesi yapın veya 5514 kullanın.

### 5.2 Filters (WEF/Winlogbeat için JSON, Syslog için Grok, Kaspersky için JSON/KV)
```conf
filter {
  # Winlogbeat (WEC -> Winlogbeat -> Logstash) JSON geldiğinde
  if [@metadata][beat] == "winlogbeat" or [event][module] == "windows" {
    mutate { add_field => { "event.module" => "windows" } }
    # ecs eşlemeleri
    if [winlog] {
      mutate { rename => { "[winlog][event_id]" => "[event][code]" } }
    }
  }

  # Syslog generic
  if [type] == "syslog" {
    grok {
      match => { "message" => "<%{NUMBER:syslog_pri}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{HOSTNAME:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      tag_on_failure => ["_grok_syslog_failure"]
    }
    date { match => ["syslog_timestamp","MMM dd HH:mm:ss","MMM  d HH:mm:ss"] }
    mutate { rename => { "syslog_hostname" => "host.name" } }
  }

  # Kaspersky JSON (KSC JSON output kullanılıyorsa)
  if [syslog_program] == "KSC" or [message] =~ "\{" {
    json { source => "message" target => "kaspersky" skip_on_invalid_json => true }
    if [kaspersky] {
      mutate { rename => { "[kaspersky][ComputerName]" => "[host][name]" } }
      mutate { rename => { "[kaspersky][ThreatName]" => "[threat][name]" } }
      mutate { add_field => { "event.module" => "kaspersky" "event.dataset" => "kaspersky.av" } }
    }
  }
}
```

### 5.3 Output (Elasticsearch + index naming / ILM)
```conf
output {
  elasticsearch {
    hosts => ["https://elasticsearch:9200"]
    user => "elastic"
    password => "${ELASTIC_PASSWORD}"
    ssl => true
    cacert => "/usr/share/logstash/config/certs/http_ca.crt"
    index => "logs-%{[event][dataset]}-%{+YYYY.MM.dd}"
    ilm_enabled => true
    ilm_policy => "logs-30d-delete"
  }
}
```

Not: `ELASTIC_PASSWORD`'ı Docker secret veya environment variable olarak güvenli şekilde verin.

## 6. Winlogbeat (WEC kolektör) örnek
`winlogbeat.yml` (WEC üzerine kurulu Winlogbeat için):

```yaml
winlogbeat.event_logs:
  - name: ForwardedEvents
    ignore_older: 72h
output.logstash:
  hosts: ["<SIEM_HOST_IP>:5044"]
```

Winlogbeat'i WEC kolektörüne kurup sadece `ForwardedEvents` kanalını izleyerek milyonlarca endpoint'e ajan kurma ihtiyacından kaçınırsınız.

## 7. rsyslog (Linux client) örnek
`/etc/rsyslog.d/60-siem.conf`:

```
*.* @@SIEM_HOST_IP:5514   # @@ = TCP, güvenlik/elyaf için TCP tercih edin
```

Sonrasında `sudo systemctl restart rsyslog`.

## 8. ILM / Index Template Örnekleri
ILM politikası (30 gün delete):

```json
PUT _ilm/policy/logs-30d-delete
{
  "policy": {
    "phases": {
      "hot": { "actions": {} },
      "delete": { "min_age": "30d", "actions": { "delete": {} } }
    }
  }
}
```

Index template:

```json
PUT _index_template/logs-template
{
  "index_patterns": ["logs-*"],
  "template": {
    "settings": { "index.lifecycle.name": "logs-30d-delete" },
    "mappings": {
      "properties": {
        "source.ip": {"type":"ip"},
        "destination.ip": {"type":"ip"},
        "user.name": {"type":"keyword"},
        "event.code": {"type":"keyword"},
        "event.module": {"type":"keyword"},
        "event.dataset": {"type":"keyword"},
        "@timestamp": {"type":"date"}
      }
    }
  }
}
```

## 9. Örnek KQL Detection Kuralları (Basic lisans için)
Aşağıdaki KQL sorgularını Kibana'da Saved Search veya manuel sorgu olarak kullanabilirsiniz. Basic lisans otomatik connector kısıtları nedeniyle bildirimleri elle veya dış araçla (ElastAlert) yapın.

- Brute-force (Windows 4625):
```
event.code:4625 and winlog.logon.type:3 and NOT user.name: "Guest"
```
Eşik (örnek): aynı `source.ip` içinde son 5 dakikada >= 5 kayıt → analist uyarı.

- Şüpheli PowerShell (4688):
```
event.code:4688 and process.name: "powershell.exe" and process.command_line: ("-enc" or "-EncodedCommand" or "IEX")
```

- Kaspersky kritik tehdit:
```
index: logs-kaspersky-* and threat.severity: "Critical"
```

- Ağ tarama (firewall deny spike): (örnek threshold kural mantığı)
```
event.dataset: "firewall" and event.action: "deny"
```
(aynı source.ip için kısa süre içinde çok sayıda farklı destination.port olması durumunda alarm çıkarılır)

## 10. Snapshot & Yedekleme
- Snapshot repo: MinIO veya S3 kullanın.
- Günlük snapshot alın ve 7/30/90 gün politikası belirleyin.

Örnek repo oluşturma:
```json
PUT _snapshot/my_s3_repo
{ "type": "s3", "settings": { "bucket": "siem-snapshots", "region": "eu-west-1" } }
```

## 11. Monitoring & Sağlık Kontrolleri
- Kibana Monitoring (Metricbeat) veya Docker host'ta Prometheus/node_exporter ile altyapıyı izleyin.
- Elasticsearch health ve Logstash queue metric'lerini düzenli check edin.

Örnek health komutu:
```bash
curl -s -u elastic:<PASSWORD> -k https://localhost:9200/_cluster/health?pretty
```

## 12. Operasyonel İpuçları ve Riskler
- Tek düğümlü (single-node) mimaride SPOF riski yüksektir; yedekleme ve hızlı kurtarma planı olmazsa veri kaybı yaşanabilir.
- Logstash CPU yükünü azaltmak için mümkün olduğunca JSON/structured format tercih edin.
- Grok pattern'larını performans için optimize edin; gereksiz ayrıştırmadan kaçının.
- Basic lisans ile e-posta/webhook otomasyonu sınırlıdır; kritik bildirimler için ElastAlert veya bir webhook-relay (ör: küçük Python/Flask servisi) kurmayı planlayın.

## 13. Hızlı Kontrol Listesi (Deploy öncesi)
- [ ] Host `vm.max_map_count` ayarlı
- [ ] Swap kapatıldı veya swappiness düşük
- [ ] NVMe data volume bağlandı ve Elasticsearch data mount edildi
- [ ] Docker daemon resource/ulimit ayarları yapıldı
- [ ] Docker Compose içinde ES_JAVA_OPTS ve LS_JAVA_OPTS ayarlandı
- [ ] Logstash pipeline'ları `./logstash/pipeline` içinde var ve test edildi
- [ ] Winlogbeat (WEC) ve rsyslog client test trafiği yapılmış
- [ ] ILM policy ve index template yüklendi
- [ ] Snapshot repo konfigüre edildi

---

Bu dosyayı repo içinde `CONFIGURATIONS.md` adıyla ekledim. İsterseniz şu eklemeleri yapabilirim:
- Tam çalışır örnek `docker-compose.yml` (tam versiyon, secret + cert yönetimi ile)
- Logstash pipeline'larının daha ayrıntılı, test edilmiş Grok desenleri
- ElastAlert veya webhook-relay için örnek küçük bir Python servis

Hangi eklemeyi istersiniz?