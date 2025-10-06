# ELK-Ubuntu-Jammy-Build

**Amaç:**
Ubuntu 22.04 (Jammy) üzerinde **tek komutla**, agentless (Elastic Agent/Fleet **kullanılmadan**) çalışan, **Elasticsearch yalnızca localhost**, **Kibana ve Logstash dışa açık** olacak şekilde güvenli ve idempotent bir **Elastic Stack (SIEM) log toplama** kurulumu sağlar.
Toplama tarafında **WEF (Windows Event Forwarding), Syslog (Linux & Ağ Cihazları) ve Kaspersky** örnek pipeline’ları ile gelir. Çıktılar **ECS** uyumlu alanlara normalize edilir ve **data stream + ILM (logs-30d)** politikasına göre yönetilir.

---

## İçindekiler

* [Özellikler](#özellikler)
* [Mimari Özet](#mimari-özet)
* [Dizin Yapısı](#dizin-yapısı)
* [Gereksinimler](#gereksinimler)
* [Hızlı Başlangıç](#hızlı-başlangıç)
* [Kurulum Sonrası](#kurulum-sonrası)
* [Log Kaynaklarını Bağlama](#log-kaynaklarını-bağlama)

  * [Windows (WEF/WEC + tek Winlogbeat)](#windows-wefwec--tek-winlogbeat)
  * [Linux & Ağ Cihazları (Syslog)](#linux--ağ-cihazları-syslog)
  * [Kaspersky (Syslog/JSON)](#kaspersky-syslogjson)
* [Veri Modeli, ILM ve Data Streams](#veri-modeli-ilm-ve-data-streams)
* [Sık Karşılaşılan Sorunlar](#sık-karşılaşılan-sorunlar)
* [Yeniden Kurulum / Sıfırlama](#yeniden-kurulum--sıfırlama)
* [Lisans](#lisans)

---

## Özellikler

* **Tek komutla kurulum:** `elk_setup_ubuntu_jammy.sh`
* **Güvenli & sade ağ modeli:**

  * **Elasticsearch:** TLS etkin, **yalnızca localhost:9200**
  * **Kibana:** `0.0.0.0:5601` (dışa açık)
  * **Logstash:** Dışa açık girişler:

    * FortiGate/Beats → **5044/tcp**
    * WEF/Winlogbeat → **5045/tcp**
    * Syslog (RFC3164) → **5514/tcp, 5514/udp**
    * Syslog (RFC5424 opsiyonel) → **5515/tcp**
    * Kaspersky → **5516/tcp, 5516/udp**
* **Sertifikalar:** CA + HTTP + Transport **PEM**, SAN: `localhost`, `127.0.0.1`, `::1`
* **Idempotent akış:** Repo/GPG temiz ekleme, `vm.max_map_count`, systemd drop-in, keystore, roller
* **ECS normalizasyonu:** kaynaklara göre temel alan eşleştirmeleri
* **Data Stream + ILM:** `logs-<dataset>-default`, politika: **logs-30d** (hot→rollover + 30 günde sil)

---

## Mimari Özet

```
[Windows Clients] --(WEF/GPO)--> [WEC] --(Winlogbeat→5045)--> [Logstash] --> [Elasticsearch (localhost TLS)]
[Linux/Network] --(Syslog 5514/5515/5516)--> [Logstash] --> [Elasticsearch]
                                                            └--> [Data Stream: logs-*-default] --(ILM logs-30d)-->
[Kullanıcı] <-- HTTP/5601 --> [Kibana UI] --(Enrollment Token + elastic)--> [Elasticsearch localhost]
```

> **Not:** Agentless hedeflenmiştir. Windows tarafında **yalnız WEC** sunucusuna **Winlogbeat** kurulması önerilir (istemcilere ajan kurulmaz).

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
* **Ağ:** İnternet erişimi (Elastic paket deposu için)
* **Haklar:** `sudo` (root) yetkisi
* **Kaynak (öneri, ~20 GB/gün):**

  * 8 vCPU / 32 GB RAM
  * NVMe/SSD depolama (≥ 1 TB, saklama politikasına göre değişir)

---

## Hızlı Başlangıç

```bash
git clone https://github.com/yusufarbc/ELK-Ubuntu-Jammy-Build.git
cd ELK-Ubuntu-Jammy-Build
chmod +x elk_setup_ubuntu_jammy.sh
sudo ./elk_setup_ubuntu_jammy.sh
```

**Betik sonunda göreceklerin:**

* **Kibana URL** (http://<sunucu_ip>:5601)
* **elastic** parolası
* **Kibana Enrollment Token**
* Logstash kullanıcı/keystore bilgisi (kullanıcı: `logstash_ingest`, parola keystore’da `ES_PW`)

---

## Kurulum Sonrası

* **Servis durumu**

  ```bash
  systemctl status elasticsearch kibana logstash --no-pager
  ```
* **ES sağlık kontrolü (TLS + CA)**

  ```bash
  curl -s --cacert /etc/elasticsearch/certs/ca.crt https://localhost:9200 | jq .
  ```
* **Logstash pipeline testi**

  ```bash
  sudo /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
  ```
* **Kibana ilk giriş**

  * Tarayıcı: `http://<sunucu_ip>:5601`
  * **Enrollment Token** → betik çıktısından
  * Kullanıcı: **elastic**, parola: betik çıktısından

---

## Log Kaynaklarını Bağlama

### Windows (WEF/WEC + tek Winlogbeat)

1. **WEC (Collector) hazırlığı** (Windows Server):

```powershell
wecutil qc
winrm quickconfig
```

2. **GPO** üzerinde istemcilere **Subscription Manager** ayarı (source-initiated), WEC adresi gösterilir.

3. **Winlogbeat (yalnız WEC’e)**:

```yaml
# C:\Program Files\Elastic\Beats\winlogbeat\winlogbeat.yml
winlogbeat.event_logs:
  - name: ForwardedEvents

output.logstash:
  hosts: ["<logstash_ip>:5045"]
  # TLS gerekirse burada CA/sertifika tanımlayın
```

> İstemcilere ajan yoktur; olaylar WEF ile WEC’e gelir, **yalnız WEC** Logstash’a gönderir.

---

### Linux & Ağ Cihazları (Syslog)

* Cihaz/host syslog hedefi: **<logstash_ip> : 5514/udp** (veya 5514/tcp)
* RFC5424 gönderiyorsanız: **5515/tcp**

**rsyslog örneği (Linux kaynak):**

```conf
# /etc/rsyslog.d/90-logstash.conf
*.*  @<logstash_ip>:5514   # UDP
#*.* @@<logstash_ip>:5514  # TCP
```

```bash
sudo systemctl restart rsyslog
```

---

### Kaspersky (Syslog/JSON)

* **Syslog** gönderebilen KSC/Agent → hedef **5516/udp,tcp**
* JSON çıkışı varsa aynı porta “raw” olarak iletebilirsiniz (pipeline JSON’u otomatik parse eder).

---

## Veri Modeli, ILM ve Data Streams

* Logstash, Elasticsearch’e **data_stream** olarak yazar:

  * `logs-<dataset>-default`
  * Dataset örnekleri: `fortigate`, `windows`, `syslog`, `kaspersky`
* **ILM politikası:** `logs-30d` (hot rollover: 25 GB/7 gün; silme: 30 gün)
* **Index template:** `logs-ds-template` (pattern: `logs-*-*`, data_stream etkin)

**Kontrol komutları:**

```bash
# Data stream listesi
curl -s --cacert /etc/elasticsearch/certs/ca.crt -u elastic:<PW> https://localhost:9200/_data_stream?pretty

# ILM policy
curl -s --cacert /etc/elasticsearch/certs/ca.crt -u elastic:<PW> https://localhost:9200/_ilm/policy/logs-30d?pretty

# Index template
curl -s --cacert /etc/elasticsearch/certs/ca.crt -u elastic:<PW> https://localhost:9200/_index_template/logs-ds-template?pretty
```

---

## Sık Karşılaşılan Sorunlar

* **Kibana ES’e bağlanamıyor**

  * ES ayakta mı? `curl https://localhost:9200` (CA ile) kontrol et
  * `/etc/kibana/kibana.yml` → `elasticsearch.hosts: ["https://localhost:9200"]`
* **Enrollment Token yok**

  ```bash
  sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
  ```
* **Logstash veri yazmıyor**

  * `journalctl -u logstash -f` ile hata oku
  * Keystore’da **ES_PW** var mı?
  * `logstash -t` ile pipeline doğrula
* **Port çatışması**

  * `sudo ss -lntup | egrep ':(5044|5045|5514|5515|5516|5601)\b'`
* **ES açılmıyor**

  * `journalctl -u elasticsearch -e`
  * Disk/izin/heap kontrolü, `vm.max_map_count=262144`

---

## Yeniden Kurulum / Sıfırlama

Sertifikaları (localhost SAN) baştan üretmek istersen:

```bash
sudo systemctl stop logstash kibana elasticsearch || true

# ES / Kibana / Logstash konfig ve sertifikalar
sudo rm -rf /etc/elasticsearch /etc/kibana /etc/logstash

# systemd drop-in (ES_LOG_DIR/ES_PATH_CONF) ve loglar
sudo rm -rf /etc/systemd/system/elasticsearch.service.d
sudo rm -rf /var/log/elasticsearch /var/log/logstash
sudo rm -rf /var/lib/elasticsearch /var/lib/logstash

# Logstash ortam dosyası (keystore parolası vs.)
sudo rm -f /etc/default/logstash /etc/sysconfig/logstash

# systemd yenile
sudo systemctl daemon-reload

# scripti yeniden başlat
sudo ./elk_setup_ubuntu_jammy.sh
```

---

## Lisans

* **Elastic Stack Basic (Ücretsiz)** özellikleri hedef alınmıştır.
* Güvenlik (TLS/auth) **etkindir**; Elasticsearch yalnızca **localhost**’tan erişilir.
* Depoya ait betik/konfigürasyonlar “as is” sağlanır; üretim için kendi politika ve güvenlik gereksinimlerinize göre gözden geçiriniz.

---

**Katkı / Geri Bildirim:**
Hataları, iyileştirme önerilerini ve ek kaynak taleplerini **Issues** bölümünden iletebilirsin. 🙌