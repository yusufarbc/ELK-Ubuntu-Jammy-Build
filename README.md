# ELK-Ubuntu-Jammy-Build

**Amaç:**
Ubuntu 22.04 (Jammy) üzerinde **tek komutla**, agentless (Elastic Agent/Fleet **yok**) çalışan, **Elasticsearch yalnızca localhost**, **Kibana ve Logstash dışa açık** olacak şekilde güvenli ve idempotent bir **Elastic Stack (SIEM) log toplama** kurulumu sağlar.
Varsayılan pipeline’lar: **WEF (Windows Event Forwarding), Syslog (Linux & Ağ cihazları) ve Kaspersky**. Çıktılar **ECS**’e yakın normalize edilir, **data_stream + ILM (logs-90d)** ile yönetilir.

---

## İçindekiler

* [Özellikler](#özellikler)
* [Mimari](#mimari)
* [Dizin Yapısı](#dizin-yapısı)
* [Gereksinimler](#gereksinimler)
* [Hızlı Başlangıç](#hızlı-başlangıç)
* [Kurulum Sonrası](#kurulum-sonrası)
* [Log Kaynaklarını Bağlama](#log-kaynaklarını-bağlama)
* [ILM ve Data Streams](#ilm-ve-data-streams)
* [Sorun Giderme](#sorun-giderme)
* [Yeniden Kurulum / Temizlik](#yeniden-kurulum--temizlik)
* [Lisans](#lisans)

---

## Özellikler

* **Tek komutla kurulum:** `elk_setup_ubuntu_jammy.sh`
* **Ağ modeli:**

  * **Elasticsearch:** `https://localhost:9200` (yalnızca localhost, TLS etkin)
  * **Kibana:** `http://0.0.0.0:5601` (dışa açık)
  * **Logstash girişleri:**

    * Beats (FortiGate vb.) → **5044/tcp**
    * WEF/Winlogbeat (WEC → LS) → **5045/tcp**
    * Syslog RFC3164 → **5514/tcp, 5514/udp**
    * Syslog RFC5424 → **5515/tcp**
    * Kaspersky → **5516/tcp, 5516/udp**
* **Sertifikalar:** CA + HTTP (PKCS#12) + Transport (PEM) — SAN: `localhost`, `127.0.0.1`, `::1`
* **Idempotent:** GPG/Repo temiz ekleme, `vm.max_map_count`, systemd drop-in, keystore, rol/kullanıcı
* **ECS’e yakın normalizasyon** ve **data_stream + ILM (90 gün)**

---

## Mimari

```
[Windows Clients] --WEF/GPO--> [WEC] --Winlogbeat(→5045/tcp)--> [Logstash] --> [Elasticsearch (localhost/TLS)]
[Linux/Network/Kaspersky] --Syslog(5514/5515/5516)--> [Logstash] --> [Elasticsearch]
Kullanıcı <-- 5601 HTTP --> Kibana --(Enrollment Token + elastic)--> Elasticsearch (localhost)
```

> Hedef “agentless”: İstemcilere ajan kurulmaz; yalnız **WEC sunucusuna Winlogbeat** kurulur.

---

## Dizin Yapısı

```
ELK-Ubuntu-Jammy-Build/
├─ elk_setup_ubuntu_jammy.sh
└─ files/
   ├─ elasticsearch/elasticsearch.yml
   ├─ kibana/kibana.yml
   └─ logstash/
      ├─ fortigate.conf
      ├─ windows_wef.conf
      ├─ syslog.conf
      └─ kaspersky.conf
```

---

## Gereksinimler

* **OS:** Ubuntu 22.04 LTS (Jammy)
* **Yetki:** root/sudo
* **Ağ:** İnternet (Elastic APT deposu)
* **Önerilen kaynak (~20 GB/gün):** 8 vCPU / 32 GB RAM / NVMe-SSD (≥1 TB, saklama politikasına göre)

---

## Hızlı Başlangıç

```bash
git clone https://github.com/yusufarbc/ELK-Ubuntu-Jammy-Build.git
cd ELK-Ubuntu-Jammy-Build
chmod +x elk_setup_ubuntu_jammy.sh
sudo ./elk_setup_ubuntu_jammy.sh
```

**Betik çıktısı (özet):**

* **Kibana URL:** `http://<Sunucu_IP_veya_FQDN>:5601`
* **Elastic** kullanıcı/parola
* **Kibana Enrollment Token**
* Logstash kullanıcı/keystore bilgisi (kullanıcı: `logstash_ingest`, parola keystore’da `ES_PW`)

---

## Kurulum Sonrası

* **Servis durumu**

  ```bash
  systemctl status elasticsearch kibana logstash --no-pager
  ```
* **Elasticsearch sağlık (TLS + CA)**

  ```bash
  curl -s --cacert /etc/elasticsearch/certs/ca.crt https://localhost:9200 | jq .
  ```
* **Logstash pipeline doğrulama**

  ```bash
  sudo /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
  ```
* **Kibana ilk giriş**

  * Tarayıcı: `http://<Sunucu_IP_veya_FQDN>:5601`
  * **Enrollment Token:** betik çıktısında
  * Kullanıcı: **elastic** (parola betik çıktısında)

---

## Log Kaynaklarını Bağlama

### Windows (WEF/WEC + tek Winlogbeat)

1. **WEC (Collector) hazırlığı** (Windows Server):

   ```powershell
   wecutil qc
   winrm quickconfig
   ```
2. **GPO:** İstemcilere **Subscription Manager** (source-initiated), WEC adresi verilir.
3. **Winlogbeat (yalnız WEC’e)** — `ForwardedEvents` → Logstash 5045/tcp gönderir:

   ```yaml
   winlogbeat.event_logs:
     - name: ForwardedEvents
   output.logstash:
     hosts: ["<logstash_host>:5045"]
   ```

### Linux & Ağ Cihazları (Syslog)

* Hedef: **5514/udp** (veya 5514/tcp), RFC5424 için **5515/tcp**
* rsyslog örneği:

  ```conf
  # /etc/rsyslog.d/90-logstash.conf
  *.*  @<logstash_host>:5514   # UDP
  #*.* @@<logstash_host>:5514  # TCP
  ```

  ```bash
  sudo systemctl restart rsyslog
  ```

### Kaspersky

* KSC/Agent syslog gönderebiliyorsa hedef: **5516/udp,tcp**
* JSON varsa aynı porta “raw” iletin (pipeline JSON’u parse eder).

---

## ILM ve Data Streams

* **Data Stream adı:** `logs-<dataset>-default` (ör. `logs-windows-default`, `logs-fortigate-default`)
* **ILM politikası:** `logs-90d` (90 günde silme)
* **Index template:** `logs-default` (pattern: `logs-*-*`, `fortigate-logs-*`; 1 shard / 0 replica / ILM=logs-90d)

Kontrol komutları:

```bash
# Data stream listesi
curl -s --cacert /etc/elasticsearch/certs/ca.crt -u elastic:<PW> https://localhost:9200/_data_stream?pretty
# ILM policy
curl -s --cacert /etc/elasticsearch/certs/ca.crt -u elastic:<PW> https://localhost:9200/_ilm/policy/logs-90d?pretty
# Index template
curl -s --cacert /etc/elasticsearch/certs/ca.crt -u elastic:<PW> https://localhost:9200/_index_template/logs-default?pretty
```

---

## Sorun Giderme

* **Kibana ES’e bağlanamıyor**

  * ES ayakta mı? `curl https://localhost:9200` (CA ile) kontrol et
  * `/etc/kibana/kibana.yml` → `elasticsearch.hosts: ["https://localhost:9200"]`
* **Enrollment Token gelmedi**

  ```bash
  sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
  ```
* **Logstash veri yazmıyor**

  * `journalctl -u logstash -f` → hata
  * Keystore’da **ES_PW** var mı?
  * `logstash -t` ile pipeline testi
* **Port çatışması**

  ```bash
  sudo ss -lntup | egrep ':(5044|5045|5514|5515|5516|5601)\b'
  ```
* **ES açılmıyor**

  * `journalctl -u elasticsearch -e`
  * Disk/izin/heap, `vm.max_map_count=262144`

---

## Yeniden Kurulum / Temizlik

```bash
sudo systemctl stop logstash kibana elasticsearch || true
sudo rm -rf /etc/elasticsearch /etc/kibana /etc/logstash
sudo rm -rf /etc/systemd/system/elasticsearch.service.d
sudo rm -rf /var/log/elasticsearch /var/log/logstash
sudo rm -rf /var/lib/elasticsearch /var/lib/logstash
sudo rm -f /etc/default/logstash /etc/sysconfig/logstash
sudo systemctl daemon-reload
# tekrar:
# cd ELK-Ubuntu-Jammy-Build && sudo ./elk_setup_ubuntu_jammy.sh
```

---

## Lisans

* **Elastic Stack Basic (Ücretsiz)** hedeflenmiştir.
* Elasticsearch yalnız **localhost**’a açıktır; Kibana ve Logstash dışa açıktır (güvenlik duvarı/SG gerekli).
* Betikler “as is” sağlanır; üretim öncesi kurum politikalarınıza göre gözden geçiriniz.

**Geri Bildirim / Issues:** memnuniyetle kabul edilir. 🙌
