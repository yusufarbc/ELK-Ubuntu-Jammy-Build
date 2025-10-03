#!/usr/bin/env bash
# deploy_remote.sh - Generic helper to deploy repo to a remote host and run the installer non-interactively
# Usage: ./deploy_remote.sh <user@host> [--ssh-key /path/to/key] [--password 'ELASTIC_PW']

set -euo pipefail
REMOTE=${1:-}
SSH_KEY=""
ELASTIC_PW=""
shift || true

while [ "$#" -gt 0 ]; do
  case "$1" in
    --ssh-key)
      SSH_KEY="$2"
      shift 2
      ;;
    --password)
      ELASTIC_PW="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [ -z "$REMOTE" ]; then
  echo "Usage: $0 user@host [--ssh-key /path] [--password 'ELASTIC_PW']"
  exit 2
fi

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
if [ -n "$SSH_KEY" ]; then
  SSH_OPTS+=" -i $SSH_KEY"
fi

echo "Copying repository to $REMOTE:/root/elk..."
scp -r $SSH_OPTS . $REMOTE:/root/elk

echo "Running installer on remote host..."
if [ -n "$ELASTIC_PW" ]; then
  ssh $SSH_OPTS $REMOTE "sudo bash /root/elk/elk_setup_ubuntu_jammy.sh --non-interactive --password '$ELASTIC_PW'"
else
  ssh $SSH_OPTS $REMOTE "sudo bash /root/elk/elk_setup_ubuntu_jammy.sh --non-interactive"
fi

echo "Deployment completed. Check the remote host for logs and Kibana at https://<REMOTE_IP>:5601"
