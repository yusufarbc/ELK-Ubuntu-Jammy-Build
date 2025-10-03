# ELK-Ubuntu-Jammy-Build

Bu repository, tek bir Ubuntu LTS (Jammy) sunucusuna agentless Elastic Stack (Elasticsearch, Kibana, Logstash) kurmak ve temel işletim/izleme ihtiyaçlarını karşılamak için örnek script ve konfigürasyonlar içerir.

## İçindekiler

- Amaç
- Hızlı Kurulum
- Kurulum Sonrası Doğrulama
- Temel Tuning
- Örnek Pipeline & Log Kaynakları
- ILM ve Kısa KQL Örnekleri

Ön Koşullar:

- Ubuntu 22.04 LTS (Jammy) kullanılması önerilir. Resmi ISO ve sürümler için: https://releases.ubuntu.com/jammy/

- Operasyon Kontrolleri
- Dosyalar ve Güvenlik Notları


## Amaç

Agentless (WEF/WEC + Winlogbeat, rsyslog vb.) yaklaşımla, tek-host üzerinde hızlı kurulup test edilebilen bir Elastic SIEM referansı sunmak.


## Hızlı Kurulum

1) Depoyu klonlayın:

```bash
git clone https://github.com/yusufarbc/ELK-Ubuntu-Jammy-Build.git
cd ELK-Ubuntu-Jammy-Build
```

2) Kurulum seçenekleri (önerilen: environment secret):

- Environment değişkeni ile (önerilir):

```bash
export ELASTIC_PASSWORD='SOME_STRONG_PW'
chmod +x elk_setup_ubuntu_jammy.sh
sudo ELASTIC_PASSWORD="$ELASTIC_PASSWORD" bash elk_setup_ubuntu_jammy.sh --non-interactive
```

- Veya doğrudan arg ile (dikkat: komut satırı görünür):

```bash
chmod +x elk_setup_ubuntu_jammy.sh
sudo bash elk_setup_ubuntu_jammy.sh --non-interactive --password 'SOME_STRONG_PW'
```

Not: Script `--dry-run` modu varsa önce onu çalıştırıp ne yapacağını gözleyin.


## Kurulum Sonrası Doğrulama

Elasticsearch çalışıyor mu?

```bash
sudo systemctl status elasticsearch
curl -u elastic:$ELASTIC_PASSWORD -k https://localhost:9200/
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

Temel tuning kontrolleri:

```bash
sysctl vm.max_map_count
ulimit -l   # elasticsearch kullanıcısı ile kontrol edin
```


## Temel Tuning (hızlı)

Uygulanması önerilen host ayarları (kalıcı):

```bash
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
sudo swapoff -a
echo -e "elasticsearch soft nofile 65536\nelasticsearch hard nofile 65536" | sudo tee /etc/security/limits.d/90-elasticsearch.conf
```

JVM heap önerisi: toplam RAM'in ~%50'si, maksimum 32 GB.


## Örnek Pipeline & Log Kaynakları (kısa)

Pipeline dosyalarını `./logstash/pipeline/` içine yerleştirin. Örnek input/output:

Inputs:

```conf
input {
  beats { port => 5044 }
  tcp  { port => 5514 type => "syslog" }
  udp  { port => 5514 type => "syslog" }
}
```

Output (örnek):

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

Winlogbeat (WEC kolektörü) için örnek:

```yaml
winlogbeat.event_logs:
  - name: ForwardedEvents
output.logstash:
  hosts: ["<SIEM_HOST_IP>:5044"]
```

rsyslog istemci örneği:

```
*.* @@SIEM_HOST_IP:5514
```


## ILM ve Kısa KQL Örnekleri

Örnek ILM (30 gün sonra silme):

```json
PUT _ilm/policy/logs-30d-delete
{
  "policy": { "phases": { "hot": {}, "delete": { "min_age": "30d", "actions": { "delete": {} } } } }
}
```

Örnek KQL (hızlı):

- Brute-force (Windows 4625):
```
event.code:4625 and winlog.logon.type:3 and NOT user.name: "Guest"
```
- Şüpheli PowerShell (komut satırı şifreleme):
```
event.code:4688 and process.name: "powershell.exe" and process.command_line: ("-enc" or "-EncodedCommand" or "IEX")
```


## Operasyon Kontrolleri (deploy öncesi)

- vm.max_map_count ayarlı
- Swap kapatıldı veya swappiness düşük
- Elasticsearch data volume mount edildi
- Logstash pipeline'ları test edildi
- ILM policy ve index template yüklendi
- Snapshot repo (S3/MinIO) konfigüre edildi


## Dosyalar ve Güvenlik Notları

- `elk_setup_ubuntu_jammy.sh` — apt tabanlı kurulum scripti (env/secrets desteği eklendi)
- `logstash/pipeline/` — pipeline örnekleri (varsa)
- `CONFIGURATIONS.md`, `SINGLE_HOST_QUICKSTART.md` — kısa yönlendirme dosyaları; detaylar README içinde

Güvenlik ve katkı:
- Gerçek şifreleri ve sertifikaları repoya koymayın.
- Üretimde TLS, erişim kontrolü ve secrets yönetimi uygulayın.

