# ELK-Ubuntu-Jammy-Build

Bu repository, tek bir **Ubuntu 22.04 LTS (Jammy)** sunucusuna *agentless* Elastic Stack (Elasticsearch, Kibana, Logstash) kurmak ve temel işletim/izleme ihtiyaçlarını karşılamak için örnek script ve konfigürasyonlar içerir.

---

## İçindekiler

- [Amaç](#amaç)  
- [Hızlı Kurulum](#hızlı-kurulum)  
- [Kurulum Sonrası Doğrulama](#kurulum-sonrası-doğrulama)  
- [Temel Tuning](#temel-tuning-hızlı)  
- [Örnek Pipeline & Log Kaynakları](#örnek-pipeline--log-kaynakları-kısa)  
- [ILM ve KQL Örnekleri](#ilm-ve-kısa-kql-örnekleri)  
- [Operasyon Kontrolleri](#operasyon-kontrolleri-deploy-öncesi)  
- [Dosyalar ve Güvenlik Notları](#dosyalar-ve-güvenlik-notları)  

---

## Amaç

Agentless (WEF/WEC + Winlogbeat, rsyslog vb.) yaklaşımla, tek host üzerinde hızlı kurulup test edilebilen bir **Elastic SIEM referansı** sunmak.

> Önerilen OS: **Ubuntu 22.04 LTS (Jammy)**  
> Resmi ISO: [https://releases.ubuntu.com/jammy/](https://releases.ubuntu.com/jammy/)

---

## Hızlı Kurulum

### 1) Depoyu klonlayın
```bash
git clone https://github.com/yusufarbc/ELK-Ubuntu-Jammy-Build.git
cd ELK-Ubuntu-Jammy-Build
```

### 2) Kurulum seçenekleri (önerilen: environment secret)

- **Environment değişkeni ile (önerilir):**
```bash
chmod +x elk_setup_ubuntu_jammy.sh
sudo bash elk_setup_ubuntu_jammy.sh --non-interactive
```

- **Veya doğrudan arg ile (komut satırında görünür):**
```bash
chmod +x elk_setup_ubuntu_jammy.sh
sudo bash elk_setup_ubuntu_jammy.sh --non-interactive --password 'SOME_STRONG_PW'
```

💡 **Not:** `--dry-run` ile önce neler yapılacağını görebilirsiniz.

---

## Kurulum Sonrası Doğrulama

### Elasticsearch
```bash
sudo systemctl status elasticsearch
curl -u elastic:$ELASTIC_PASSWORD -k https://localhost:9200/
```

### Kibana
```bash
sudo systemctl status kibana
curl -k https://localhost:5601/ -I
```

### Logstash
```bash
sudo systemctl status logstash
```

### Temel tuning kontrolleri
```bash
sysctl vm.max_map_count
sudo -u elasticsearch bash -c 'ulimit -l'
```

---

### Elasticsearch kullanıcısı altında komut çalıştırma

- **Tek komut (önerilen):**
```bash
sudo -u elasticsearch bash -c 'ulimit -l'
sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -s -b
```

- **Shell açmak (opsiyonel, her sistemde çalışmayabilir):**
```bash
sudo -i -u elasticsearch
# veya
sudo -u elasticsearch /bin/bash
```

🔎 **Notlar:**  
- `elasticsearch` kullanıcısıyla çalıştırılan bazı komutlar root yetkisi gerektirebilir.  
- Enrollment token/parola sıfırlama işlemleri yalnızca Elasticsearch sağlıklı çalışıyorsa başarılı olur.  

Hata incelemek için:
```bash
sudo systemctl status elasticsearch
sudo journalctl -u elasticsearch -b --no-pager | tail -n 100
```

Otomatik üretilmiş parolayı görmek için (sadece root):
```bash
sudo cat /root/.elastic_pw
```

---

## Temel Tuning (hızlı)

```bash
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
sudo swapoff -a
echo -e "elasticsearch soft nofile 65536
elasticsearch hard nofile 65536" | sudo tee /etc/security/limits.d/90-elasticsearch.conf
```

💡 JVM heap: Toplam RAM’in %50’si, maksimum **32 GB** önerilir.

---

## Örnek Pipeline & Log Kaynakları (kısa)

Pipeline dosyaları: `./logstash/pipeline/`

### Inputs
```conf
input {
  beats { port => 5044 }
  tcp  { port => 5514 type => "syslog" }
  udp  { port => 5514 type => "syslog" }
}
```

### Output (örnek)
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

### Winlogbeat (WEC kolektörü) örnek
```yaml
winlogbeat.event_logs:
  - name: ForwardedEvents
output.logstash:
  hosts: ["<SIEM_HOST_IP>:5044"]
```

### rsyslog istemci örneği
```
*.* @@SIEM_HOST_IP:5514
```

---

## ILM ve Kısa KQL Örnekleri

### Örnek ILM (30 gün sonra silme)
```json
PUT _ilm/policy/logs-30d-delete
{
  "policy": {
    "phases": {
      "hot": {},
      "delete": {
        "min_age": "30d",
        "actions": { "delete": {} }
      }
    }
  }
}
```

### Örnek KQL
- **Brute-force (Windows 4625):**
```
event.code:4625 and winlog.logon.type:3 and NOT user.name: "Guest"
```

- **Şüpheli PowerShell:**
```
event.code:4688 and process.name: "powershell.exe" and process.command_line: ("-enc" or "-EncodedCommand" or "IEX")
```

---

## Operasyon Kontrolleri (deploy öncesi)

- `vm.max_map_count` ayarlı  
- Swap kapatıldı veya swappiness düşük  
- Elasticsearch data volume mount edildi  
- Logstash pipeline test edildi  
- ILM policy ve index template yüklendi  
- Snapshot repo (S3/MinIO) konfigüre edildi  

---

## Dosyalar ve Güvenlik Notları

- `elk_setup_ubuntu_jammy.sh` → apt tabanlı kurulum scripti (env/secrets desteğiyle)  
- `logstash/pipeline/` → pipeline örnekleri  
- `CONFIGURATIONS.md`, `SINGLE_HOST_QUICKSTART.md` → kısa yönlendirme dokümanları  

🔒 **Güvenlik ve katkı:**  
- Gerçek şifreleri ve sertifikaları repoya koymayın.  
- Üretimde TLS, erişim kontrolü ve secrets yönetimi uygulayın.  

---
