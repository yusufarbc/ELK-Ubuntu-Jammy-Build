Bu dizin `examples/` altında Winlogbeat, rsyslog snippetleri, Kaspersky örnek JSON, ILM policy ve index template örnekleri bulunmaktadır.

Kullanım:
- `examples/winlogbeat/winlogbeat.yml` -> WEF kolektörü üzerindeki Winlogbeat için örnek.
- `examples/rsyslog/60-siem.conf` -> Rsyslog istemcisine eklenebilecek bir satır.
- `examples/kaspersky/sample_kaspersky.json` -> Kaspersky'den gelebilecek örnek JSON event.
- `examples/ilm/logs-30d-delete.json` -> ILM policy (Kibana Dev Tools veya curl ile PUT _ilm/policy/logs-30d-delete).
- `examples/index_template/logs-template.json` -> Index template (PUT _index_template/logs-template).
- `examples/kql/saved_searches.md` -> Bazı KQL sorgu örnekleri.

Helper scriptler:
- `scripts/lab_start.sh` -> Sertifikaları üretir (gerekirse) ve non-docker tek-host kurulum veya test talimatları verir.
- `scripts/load_ilm_and_template.sh` -> ILM policy ve index template'i Elasticsearch'e yükler (ELASTIC_PASSWORD gerektirir).
- `scripts/send_kaspersky_sample.sh` -> `examples/kaspersky/sample_kaspersky.json` içeriğini Logstash syslog portuna gönderir (test amaçlı).
- `scripts/check_es_for_kaspersky.sh` -> Elasticsearch içinde parselenmiş Kaspersky eventlerini arar (ELASTIC_PASSWORD gerektirir).

Örnek ILM yükleme (curl):

```bash
curl -u elastic:$ELASTIC_PASSWORD -k -X PUT "https://localhost:9200/_ilm/policy/logs-30d-delete" -H 'Content-Type: application/json' -d @examples/ilm/logs-30d-delete.json
```

Örnek index template yükleme:

```bash
curl -u elastic:$ELASTIC_PASSWORD -k -X PUT "https://localhost:9200/_index_template/logs-template" -H 'Content-Type: application/json' -d @examples/index_template/logs-template.json
```

Scriptleri çalıştırmadan önce çalıştırılabilir yapın:

```bash
chmod +x scripts/*.sh
```

Logstash test harness (lokal pipeline tuning için)
-----------------------------------------------
Kısa: `tools/logstash_test` dizininde Docker gerektirmeyen bir Python tabanlı test harness vardır. Bu harness ile Logstash filtrelerinizi yerel örnek loglarla hızlıca doğrulayabilirsiniz.

1) Test harness çalıştırma (Python 3 gerektirir):

```bash
cd tools/logstash_test
python3 run_test_harness.py
```

2) Çıktıyı kontrol edin:

```bash
cat tools/logstash_test/output/output.json
```

Bu harness, `tools/logstash_test/pipeline/00-test.conf` içindeki örnek mantığı taklit eder; gerçek pipeline'ınızı test etmek için örnek dosyalarınızı `tools/logstash_test/samples/` içine koyup tekrar çalıştırın.
