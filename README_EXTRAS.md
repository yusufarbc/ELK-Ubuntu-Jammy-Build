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

Cloud-init ve uzak deploy
-------------------------

İki hazır yol vardır:

1) cloud-init (provider destekliyorsa)

 - Dosya: `cloud-init/cloud-init.yml`
 - Kullanım: Cloud sağlayıcınızın "user-data" veya "cloud-init" alanına `cloud-init/cloud-init.yml` içeriğini koyun ve `REPLACE_ME` yerine güçlü bir parola girin (veya sağlayıcının secrets mekanizmasını kullanın).

2) Doğrudan SSH deploy

 - Script: `deploy_remote.sh`
 - Örnek kullanım:

```bash
# scp + ssh ile kopyala ve installer'ı non-interactive çalıştır
./deploy_remote.sh root@1.2.3.4 --ssh-key /path/to/key --password 'SOME_STRONG_PW'
```

Script şu adımları yapar: repo'yu `/root/elk` olarak kopyalar ve uzak makinede `sudo bash /root/elk/elk_setup_ubuntu_jammy.sh --non-interactive --password 'PW'` çalıştırır.

Güvenlik Notu: Parolaları komut satırında doğrudan vermek terminal geçmişinde saklanabilir. Mümkünse cloud provider secrets veya SSH agent/temporary env kullanın.

