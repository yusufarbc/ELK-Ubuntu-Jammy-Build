Ek kullanım seçenekleri ve CI
---------------------------

Non-interactive / otomasyon:

 - `elk_setup_ubuntu_jammy.sh` script'i artık `--password <pw>` (veya `-p <pw>`) ile parola alabilir ve `--non-interactive` bayrağı ile interaktif prompt olmadan çalıştırılabilir. Örnek:

```bash
sudo bash ./elk_setup_ubuntu_jammy.sh --password "SOME_STRONG_PW" --non-interactive
```

Local test harness:

 - Pipeline filtrelerini hızlıca test etmek için repo içindeki Python harness kullanılabilir (Docker gerektirmez):

```bash
python3 tools/logstash_test/run_test_harness.py
```

 - Basit assertion testleri:

```bash
pytest -q tools/logstash_test/test_harness.py
```

CI (GitHub Actions):

 - Repo'ya eklenen workflow (`.github/workflows/logstash-test.yml`) her push veya PR'de harness'i çalıştırır ve `tools/logstash_test/test_harness.py` testlerini koşar.

Notlar:

 - CI, harness'i çalıştırmadan önce `pip install pytest` yapar. Lokal makinenizde de pytest yoksa `pip install pytest` ile yükleyin.
