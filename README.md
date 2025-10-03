# ELK-Ubuntu-Jammy-Build

Bu repo, tek bir Ubuntu LTS sunucusu üzerinde Docker kullanmadan Elastic Stack 8.x (Elasticsearch, Kibana, Logstash) kurulumunu kolaylaştırmak için hazırlanmış örnek bir otomasyon scripti ve rehber içerir. Amaç: agentless log toplama mimarisi kurmak (Windows Event Forwarding + Winlogbeat, syslog ile Linux ve ağ cihazları, Kaspersky AV logları) ve Elastic Security ile temel güvenlik tespitleri üretmektir.

Dil: Türkçe

Dosyalar
- `elk_setup_ubuntu_jammy.sh` — Otomatik kurulum scripti (Ubuntu LTS). Script root olarak çalıştırılmalıdır.

Not: Ek kullanım seçenekleri, CI ve otomasyon talimatları için `README_EXTRAS.md` dosyasına bakın.

Hızlı başlangıç

1) Script'i sunucuya kopyalayın ve çalıştırın (root/sudo):

```bash
sudo bash ./elk_setup_ubuntu_jammy.sh
```

2) Script tamamlandığında ekranda `elastic` kullanıcısı için atanan parola ve (varsa) Kibana enrollment token bilgisi gösterilecektir. Kibana'yı açın: `https://<SUNUCU_IP>:5601` ve enrollment sürecini tamamlayın.

Önemli notlar
- Script temel bir kurulum yapar. Üretim ortamında TLS, kullanıcı yönetimi, backup (snapshot), monitoring (Metricbeat) ve güvenlik politikalarını el ile doğrulayın.
- Script Logstash için varsayılan syslog portu `514` (TCP/UDP) ve Beats portu `5044` kullanır. Bu portlar root ayrıcalığı gerektirdiğinden sunucunuzda uygun firewall ve güvenlik düzenlemelerini yapın.
- Basic lisans ile Kibana Connectors (e-posta/webhook) sınırlı olabilir. Harici bildirimler için deneme lisansı kullanabilir veya alternatif olarak ElastAlert gibi araçlarla webhook/email relay kurabilirsiniz.

Mimari (özet)
- Tek Ubuntu LTS sunucusu üzerinde Elasticsearch (tek düğüm/`single-node`), Kibana ve Logstash çalışır.
- Windows logları: Domain içinde WEF (Windows Event Forwarding) kullanılarak bir WEC kolektöründe toplanır. Winlogbeat sadece WEC üzerine kurulur ve Logstash 5044'e gönderir.
- Linux / ağ cihazları: rsyslog/syslog-ng ile Logstash'ın dinlediği portlara log gönderilir (varsayılan script'te 514/tcp+udp veya 5514 tercih edilebilir).
- Kaspersky: Kaspersky Security Center (KSC) üzerinden SIEM/syslog entegrasyonu etkinleştirilir; JSON veya key=value (structured) formatı önerilir.

Winlogbeat (WEF kolektör) - örnek `winlogbeat.yml`
```yaml
winlogbeat.event_logs:
  - name: ForwardedEvents
    ignore_older: 72h
output.logstash:
  hosts: ["<SIEM_HOST_IP>:5044"]
```
Kayıtlı WEF kolektöründe yalnızca `ForwardedEvents` kanalını izlemek yönetimi kolaylaştırır.

Linux / rsyslog örneği (istemci)
```
# /etc/rsyslog.d/60-siem.conf
*.* @@SIEM_HOST_IP:514   # @@ = TCP, tek @ olursa UDP
```

Kaspersky Security Center
- KSC yönetim konsolunda SIEM Integration seçeneğini aktif edin ve format olarak `JSON` seçin.
- Hedef olarak SIEM sunucusunun IP ve Logstash portunu (ör. `514/TCP`) girin.

Logstash - temel pipeline (özet)
- Script içinde `/etc/logstash/conf.d/00-siem.conf` örneği oluşturulur. Özet:
  - `input`: beats 5044, tcp/udp 514
  - `filter`: syslog grok, date; JSON parse (Kaspersky için)
  - `output`: Elasticsearch, index şablonu `logs-%{[event.dataset]}-%{+YYYY.MM.dd}`

ILM ve index template (örnek komutlar Kibana Dev Tools veya curl ile)

ILM policy (30 gün delete):
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
Index template (basit ECS alan tipleri):
```json
PUT _index_template/logs-template
{
  "index_patterns": ["logs-*"],
  "template": {
    "settings": { "index.lifecycle.name": "logs-30d-delete" },
    "mappings": {
      "properties": {
        "source.ip": { "type": "ip" },
        "destination.ip": { "type": "ip" },
        "user.name": { "type": "keyword" },
        "event.code": { "type": "keyword" },
        "event.module": { "type": "keyword" },
        "event.dataset": { "type": "keyword" },
        "@timestamp": { "type": "date" }
      }
    }
  }
}
```

Temel Detection (KQL) örnekleri ve MITRE eşlemesi
- Senaryo A — Brute-force (Windows 4625):
  - KQL: `event.code: "4625" and event.action: "logon_failure"`
  - Threshold rule: same source.ip içinde 5 dakika içinde >= 5 event.
  - MITRE: Credential Access (T1110)

- Senaryo B — Şüpheli komut / Execution (PowerShell):
  - KQL: `process.name: "powershell.exe" and process.command_line: ("-enc" or "-EncodedCommand" or "IEX" )`
  - MITRE: Execution (T1059)

- Senaryo C — Ağ tarama (firewall deny spike):
  - KQL: `event.dataset: "firewall" and event.action: "deny" and source.ip: *`
  - Threshold: tek source.ip için kısa sürede çok sayıda farklı destination.port
  - MITRE: Discovery / Network Scanning

- Senaryo D — SMB exfiltration (büyük dosya erişimleri):
  - KQL: `event.dataset: "windows.security" and (event.code: "4663" or event.code: "4656") and file.size: > 100000000` (100MB örnek)
  - MITRE: Exfiltration (T1041 veya Data Staged)

Not: KQL örnekleri ortamınıza gelen alan isimlerine göre (ör. `file.size`, `process.command_line`) uyarlanmalıdır. Logstash filtreleriyle ECS alanlarını eşlemeniz önerilir.

Alarm bildirimleri
- Basic lisans ile Kibana’nın bazı connector'ları kısıtlı olabilir. Harici e-posta/webhook gerekiyorsa:
  - Deneme lisansına geçin (30 gün) veya
  - ElastAlert / custom webhook relay ile Kibana alert sonuçlarını harici e-posta/webhook servisine gönderin.

Deep-research prompt (kendi AI asistanınıza verilecek, Türkçe)

```
Siz bir siber güvenlik mühendisisiniz. Hedef: Ubuntu LTS üzerinde single-host, agentless Elastic SIEM (Elastic 8.x, Basic). Aşağıdaki başlıklar için Türkçe detaylı bir rehber oluşturun: donanım gereksinimleri; paket reposu ve kurulum komutları; Elasticsearch/Kibana/Logstash için production-ready sistem tuning (vm.max_map_count, nofile, swap, JVM heap); çoklu node kriterleri (tek-host içinde multi-node alternatifi); WEF/Winlogbeat konfigürasyonu; rsyslog ve firewall syslog yönlendirme örnekleri; Kaspersky Security Center -> JSON/syslog entegrasyonu ve örnek event; Logstash pipeline örnekleri (grok/json/dissect ile ECS eşleme); ILM ve index template örnekleri; Kibana Detection Engine için örnek KQL kuralları (Brute-force, Execution, Discovery, Exfiltration) ve MITRE eşlemeleri; Basic lisans kısıtları ve alternatif bildirim çözümleri (ElastAlert, webhook relay). Her adım için uygulanabilir komutlar, config snippets ve dikkat edilmesi gereken güvenlik/operasyonel noktaları verin.
```

Sonraki adımlar / öneriler
- Kibana'ya bağlanıp Detection Engine > Load prebuilt rules yapın.
- WEF kolektörüne Winlogbeat kurup Logstash'a yönlendirin.
- Firewall ve Linux cihazlarında rsyslog'u test ederek log akışını doğrulayın.
- Kaspersky tarafında JSON formatı seçip küçük bir test event'i gönderin ve Logstash ile parse edin.
- ILM, snapshot repo ve yedekleme planını oluşturun.

Katkı ve güvenlik
- Bu repo örnek amaçlıdır. Parolalar, IP'ler ve hassas veriler kaydedilmemelidir.
- Üretimde TLS sertifikaları ve erişim kısıtlamaları uygulanmalıdır.

Sertifikalar (test, self-signed) ve Docker Compose ile başlatma

1) Test sertifikaları üret
- Lab ortamı için repo kökünde:

```bash
chmod +x tools/generate-self-signed-certs.sh
sudo tools/generate-self-signed-certs.sh
```

Bu script `./certs` dizini altında bir CA ve servis sertifikalarını oluşturur (elasticsearch, kibana, logstash). `docker-compose.yml` dosyası bu dizini konteynerlerde `/usr/share/.../certs` olarak mount eder.

2) ELASTIC_PASSWORD ayarla ve compose başlat
- Parolayı bir çevre değişkeni olarak ayarlayın (örnek):
```bash
export ELASTIC_PASSWORD="SOME_STRONG_PASSWORD"
docker compose up -d
```

- İlk kez çalıştırırken Elasticsearch kurulum loglarını izleyin; Kibana'ya `https://<SUNUCU_IP>:5601` ile bağlanın ve enrollment sürecini tamamlayın.


Pipeline testi ve commit öncesi kontrol
------------------------------------

1) Scriptleri çalıştırılabilir yapın (commit öncesi yerelde test etmek için):

```bash
chmod +x scripts/*.sh
```

2) `20-filters.conf` içindeki desenleri test etmek için (önerilen akış):

- Kopyalayın veya düzenleyin: `logstash/pipeline/20-filters.conf` dosyanızda yapacağınız değişiklikleri önce `tools/logstash_test/pipeline/00-test.conf` içine kopyalayın veya doğrudan `tools/logstash_test/pipeline/` altına yeni bir dosya ekleyin.
- Test harness'i başlatın:

```bash
cd tools/logstash_test
docker compose up --build
```

- Çıktıyı kontrol edin:

```bash
cat tools/logstash_test/output/output.json
docker logs -f logstash_test
```

3) Commit öncesi hızlı kontrol listesi

- `chmod +x scripts/*.sh` ile scriptlere izin verin (gerekiyorsa).
- `tools/generate-self-signed-certs.sh` ile `./certs` oluşturduysanız, `certs/` dizinini commit etmeyin — takip etmek istemezsiniz. Repo kökünde `.gitignore` dosyası bu dizini yok sayacak şekilde ayarlanmıştır.
- Değişiklikleri commit etmeden önce test harness çıktısını doğrulayın ve `logstash/pipeline/20-filters.conf` içindeki grok desenlerinin sample loglar üzerinde doğru çalıştığını teyit edin.

4) Basit commit örneği

```bash
git add -A
git commit -m "logstash: tune filters for kaspersky/asa/fortigate; add test harness samples"
git push origin main
```

Not: Bu repo tercihli olarak hassas içerikleri (sertifikalar, gerçek örnek loglar) saklamamalıdır. Gerçek üretim loglarını buraya eklemeyin.

```
