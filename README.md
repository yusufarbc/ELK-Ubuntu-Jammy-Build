echo -e "elasticsearch soft nofile 65536\nelasticsearch hard nofile 65536" | sudo tee /etc/security/limits.d/90-elasticsearch.conf
# ELK-Ubuntu-Jammy-Build

Bu repository, tek bir Ubuntu LTS (Jammy) sunucusu üzerine agentless Elastic Stack (Elasticsearch, Kibana, Logstash) kurulumunu hızla başlatmak ve temel operasyonları yürütmek için hazırlanmıştır. İçerik: non-interactive kurulum scripti, örnek Logstash pipeline'ları ve konfigürasyon notları.

## İçindekiler

- [Amaç](#amaç)
- [Hızlı Kurulum](#hızlı-kurulum)
- [Kurulum Sonrası Doğrulama](#kurulum-sonrası-doğrulama)
- [Mimari ve Topoloji Notları](#mimari-ve-topoloji-notları)
- [Temel Sistem Tuning](#temel-sistem-tuning)
- [Logstash Pipeline Örnekleri (özet)](#logstash-pipeline-örnekleri-özet)
- [Winlogbeat / rsyslog Örnekleri](#winlogbeat--rsyslog-örnekleri)
- [ILM ve Index Template Örnekleri](#ilm-ve-index-template-örnekleri)
- [KQL Örnekleri (hızlı)](#kql-örnekleri-hızlı)
- [Operasyon & Riskler](#operasyon--riskler)
- [Öne Çıkan Dosyalar](#öne-çıkan-dosyalar)
- [Güvenlik ve Katkı Notları](#güvenlik-ve-katkı-notları)


## Amaç

Orta ölçekli kurumlar için düşük maliyetle, ajan kullanmadan (WEF/WEC + Winlogbeat, rsyslog vb.) çalışabilecek, tek sunucuda hızlıca kurulabilen bir Elastic SIEM referansı sunmak.


## Hızlı Kurulum

1. Depoyu klonlayın:

```bash
git clone https://github.com/yusufarbc/ELK-Ubuntu-Jammy-Build.git
cd ELK-Ubuntu-Jammy-Build
```

2. Script'i çalıştırılabilir yapın ve kurun:

```bash
chmod +x elk_setup_ubuntu_jammy.sh
sudo bash elk_setup_ubuntu_jammy.sh --non-interactive --password 'SOME_STRONG_PW'
```

Not: Script single-node varsayılanları ve temel tuning'i uygular. Test amaçlı `--dry-run` destekleniyorsa kullanın.

Güvenli parola kullanımı (önerilen):

- Ortam değişkeni ile:

```bash
export ELASTIC_PASSWORD='SOME_STRONG_PW'
sudo bash elk_setup_ubuntu_jammy.sh --non-interactive
```

- Docker secrets veya container secret dosyası kullanıyorsanız `/run/secrets/elastic_password` dosyasına parolayı koyup script'i `--non-interactive` ile çalıştırabilirsiniz. Script bu kaynakları otomatik kontrol eder.


## Kurulum Sonrası Doğrulama

Elasticsearch:

```bash
sudo systemctl status elasticsearch
curl -u elastic:'SOME_STRONG_PW' -k https://localhost:9200/
```

Kibana:

```bash
sudo systemctl status kibana
curl -k https://localhost:5601/ -I
```

Logstash:

```bash
sudo systemctl status logstash
```

Sistem tuning kontrolleri:

```bash
sysctl vm.max_map_count
ulimit -l   # elasticsearch kullanıcısı ile kontrol edin
```


## Mimari ve Topoloji Notları

- Bu referans single-host (lab/small infra) içindir. Üretimde HA, TLS ve secrets yönetimi zorunludur.
- Log akışı örneği: Windows → WEF/WEC → Winlogbeat → Logstash → Elasticsearch
- Linux/Network → rsyslog → Logstash → Elasticsearch


## Temel Sistem Tuning

Kalıcı uygulanması önerilen host ayarları:

```bash
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
sudo swapoff -a
echo -e "elasticsearch soft nofile 65536\nelasticsearch hard nofile 65536" | sudo tee /etc/security/limits.d/90-elasticsearch.conf
```

JVM heap: toplam RAM'in yaklaşık yarısı, maksimum 32 GB.


## Logstash Pipeline Örnekleri (özet)

Pipeline'ları `./logstash/pipeline/` içine koyun (10-inputs.conf, 20-filters.conf, 30-outputs.conf).

Inputs örneği:

```conf
input {
  beats { port => 5044 }
  tcp  { port => 5514 type => "syslog" }
  udp  { port => 5514 type => "syslog" }
}
```

Temel filter örnekleri: Winlogbeat JSON eşleme, syslog için grok ve Kaspersky JSON parse. (Detaylar `CONFIGURATIONS.md` veya pipeline dosyalarında.)

Output örneği (ILM & index isimlendirme):

```conf
output {
  elasticsearch {
    hosts => ["https://elasticsearch:9200"]
    user => "elastic"
    password => "${ELASTIC_PASSWORD}"
    index => "logs-%{[event][dataset]}-%{+YYYY.MM.dd}"
    ilm_enabled => true
    ilm_policy => "logs-30d-delete"
  }
}
```

Güvenlik: `ELASTIC_PASSWORD` secret olarak verilmelidir; komut satırında açık paylaşmayın.


## Winlogbeat / rsyslog Örnekleri

Winlogbeat (WEC kolektörüne kurulu) - örnek:

```yaml
winlogbeat.event_logs:
  - name: ForwardedEvents
output.logstash:
  hosts: ["<SIEM_HOST_IP>:5044"]
```

rsyslog istemci örneği (`/etc/rsyslog.d/60-siem.conf`):

```
*.* @@SIEM_HOST_IP:5514
```


## ILM ve Index Template Örnekleri

ILM (örnek): 30 gün sonra silme.

Basit index template örneği ve ILM politikası `CONFIGURATIONS.md` içinde bulunmaktadır.


## KQL Örnekleri (hızlı)

- Brute-force (Windows 4625):
```
event.code:4625 and winlog.logon.type:3 and NOT user.name: "Guest"
```
- Şüpheli PowerShell:
```
event.code:4688 and process.name: "powershell.exe" and process.command_line: ("-enc" or "-EncodedCommand" or "IEX")
```
- Ağ tarama (firewall deny):
```
event.dataset: "firewall" and event.action: "deny"
```

KQL örnekleri ortamınıza göre uyarlanmalıdır.


## Operasyon & Riskler

- Single-node topoloji SPOF içerir; üretimde çok düğümlü cluster ve yedekleme şarttır.
- Logstash performansı için mümkünse structured/JSON log gönderin.
- Basic lisans bazı otomasyonları kısıtlayabilir; bildirimler için ElastAlert veya webhook-relay düşünün.


## Öne Çıkan Dosyalar

- `elk_setup_ubuntu_jammy.sh` — apt tabanlı kurulum scripti
- `logstash/pipeline/` — pipeline örnekleri
- `CONFIGURATIONS.md`, `SINGLE_HOST_QUICKSTART.md` — detaylı notlar (repo içinde)
- `cloud-init/`, `deploy_remote.sh` — uzak kurulum yardımcıları


## Güvenlik ve Katkı Notları

- Bu repo örnek amaçlıdır; gerçek şifreleri ve sertifikaları repoya koymayın.
- Üretimde TLS, erişim kontrolü ve secrets yönetimi uygulayın.
- `certs/` dizinini commit etmeyin.


---

Bu README, gereksiz tekrarlar ve İngilizce paragraflar çıkarılarak sadeleştirilmiş bir Türkçe kılavuzdur. Daha fazla sadeleştirme, ek örnek veya başka bir yapı istiyorsanız söyleyin.
