Cleanup summary — repo trimmed for single-host, Docker-less installer
=================================================================

Purpose
-------
This repository's intent was clarified: focus on a Docker-less, apt-based single-host Elastic Stack (Ubuntu Jammy) installer for on-prem SIEM. To reduce noise and avoid shipping large, unrelated artifacts, I trimmed and consolidated the repo.

What I removed or trimmed
------------------------
- Docker-focused artifacts were deprecated (docker-compose is preserved as a short notice file). The repo no longer promotes a containerized workflow by default.
- Long-form DOC (`source`) was trimmed (replaced with a short note). If you need specific parts restored, tell me which chapters.
- Large PDF cheat sheet remains in the repo currently (binary handling limited here); consider removing it if unnecessary to shrink repo size.
- tools/logstash_test/docker-compose.yml was replaced with a note (test harness remains as Python-based runner).

Why
---
The user requested the repo to be optimized for a single-host Ubuntu Jammy install (no Docker). Large docs and Docker artifacts made the repo confusing and heavy. Trimming keeps the repo focused, smaller, and easier to maintain for the specified use-case.

What changed/where to look
-------------------------
- `elk_setup_ubuntu_jammy.sh` — installer tuned for single-host, non-interactive use (vm.max_map_count, limits, heap auto, systemd override, uses 5514 for syslog input).
- `logstash/pipeline/` — filter improvements and ECS mapping retained.
- `SINGLE_HOST_QUICKSTART.md` — step-by-step quickstart added.
- `README.md`, `README_EXTRAS.md` — updated to reflect Docker-less intent and cloud-init/deploy options.
- `CLEANUP_NOTES.md` — this file (this note) records the pruning action.

If you want me to fully delete any remaining large binary (the PDF) or restore selected parts of the long-form guide, say which parts to remove or restore and I'll apply the changes and commit.
