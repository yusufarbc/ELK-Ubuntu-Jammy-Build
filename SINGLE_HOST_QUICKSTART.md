# SINGLE_HOST_QUICKSTART.md

**Bu belge, Elastic Stack single-host kurulumunu hızlıca başlatmak ve doğrulamak için adım adım rehber sunar.**

Kurulum öncesi mimari ve pipeline detayları için: [CONFIGURATIONS.md](CONFIGURATIONS.md)

---

## Hızlı Başlangıç
1. Depoyu klonlayın ve kurulum scriptini çalıştırın (detaylar için README.md'ye bakınız).
2. Kurulumdan sonra aşağıdaki adımlarla servisleri doğrulayın:
	- Elasticsearch, Kibana, Logstash servis durumunu kontrol edin.
	- Kurulum sonrası temel sistem tuning ayarlarını doğrulayın.

## Temel Komutlar ve Doğrulama
...existing code...
**Daha fazla mimari ve pipeline örneği için:** [CONFIGURATIONS.md](CONFIGURATIONS.md)

Single-host ELK Quickstart (Ubuntu Jammy)
======================================

This repository includes a non-interactive installer and helper artifacts for installing a single-node (development / small lab) Elastic Stack (Elasticsearch, Kibana, Logstash) on Ubuntu LTS (Jammy). Use these steps to provision a single host quickly and verify the installation.

Important: single-node setups are suitable for testing, development, and small labs. For production use, follow Elastic's clustering, security, and high-availability guidance.

Prerequisites
-------------
- A fresh Ubuntu 22.04 LTS (Jammy) instance (or compatible) with root or sudo access.
- Network access to download Elastic packages (artifacts.elastic.co).
- If using the included cloud-init or deploy script, an SSH key and/or control over the cloud provider.

Quick steps (local or remote)
-----------------------------

1) Clone repo on target host (or copy it):

```bash
git clone https://github.com/<your-repo>/ELK-Ubuntu-Jammy-Build.git /root/elk
cd /root/elk
```

2) Run the installer non-interactively with a supplied Elastic password (replace with a strong password):

```bash
sudo bash elk_setup_ubuntu_jammy.sh --non-interactive --password 'SOME_STRONG_PW'
```

Notes:
- The script will set recommended single-node defaults: `discovery.type: single-node`, `network.host: 0.0.0.0`, `bootstrap.memory_lock: true`, `vm.max_map_count=262144`, and a systemd override that sets `ES_JAVA_OPTS` to ~50% of system RAM (capped at 32 GB).
- The script supports `--dry-run` to see actions without installing packages.

Using cloud-init
----------------
- If your cloud provider supports user-data, use `cloud-init/cloud-init.yml` as the user-data payload. Replace the placeholder `REPLACE_ME` with a secure password or inject it via provider secrets.

Using the deploy helper
-----------------------
- `deploy_remote.sh` copies the repo to a remote machine and runs the installer non-interactively. Example:

```bash
./deploy_remote.sh root@1.2.3.4 --ssh-key /path/to/key --password 'SOME_STRONG_PW'
```

Basic verification
------------------

- Check Elasticsearch is running:

```bash
sudo systemctl status elasticsearch
curl -u elastic:'SOME_STRONG_PW' -k https://localhost:9200/
```

- Check Kibana is running (note Kibana may need enrollment on first boot):

```bash
sudo systemctl status kibana
curl -k https://localhost:5601/ -I
```

- Check Logstash is running:

```bash
sudo systemctl status logstash
```

- Confirm system tuning applied:

```bash
sysctl vm.max_map_count
ulimit -l   # run as elasticsearch user to confirm memlock
cat /etc/systemd/system/elasticsearch.service.d/override.conf
```

Security & Production Notes
---------------------------

- Exposing services on `0.0.0.0` is convenient for labs but dangerous in production. Use firewall rules (ufw, iptables) or private networks.
- Use TLS and proper secrets management for production (do not pass passwords on the command line). Consider using cloud provider secrets or Vault.
- Single-node is not HA — expect data loss risk if the host fails. For production, deploy a cluster with multiple master/data nodes and dedicated ingest nodes.

Troubleshooting tips
--------------------
- If Elasticsearch fails to start, check `journalctl -u elasticsearch -b` and `/var/log/elasticsearch/`.
- If Kibana stalls on enrollment, use the `KIBANA_TOKEN` printed by the installer to enroll the instance, or consult the Kibana logs (`/var/log/kibana/`).
- If Logstash pipelines fail, use `sudo journalctl -u logstash -b` and inspect `/etc/logstash/conf.d/`.

Next steps
----------
- If you'd like, I can generate a provider-specific cloud-init (AWS/GCE/Hetzner/DigitalOcean) or a Terraform starter that uses `cloud-init/cloud-init.yml` to provision VMs automatically.

License: project files follow repo license. Use responsibly.
