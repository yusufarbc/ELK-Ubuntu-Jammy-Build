#!/usr/bin/env bash
set -euo pipefail

### ======== KULLANICI AYARLARI (gerekirse değiştir) ========
ES_URL="${ES_URL:-https://localhost:9200}"
CA_CERT="${CA_CERT:-/etc/logstash/certs/ca.crt}"       # yoksa /etc/elasticsearch/certs/ca.crt
ELASTIC_USER="${ELASTIC_USER:-elastic}"               # ES’e admin yetkili kullanıcı
ELASTIC_PW="${ELASTIC_PW:-}"                          # boşsa script soracak (gizli)
ROLE_NAME="${ROLE_NAME:-logstash_windows_writer}"
LS_USER="${LS_USER:-logstash_ingest}"
LS_PW="${LS_PW:-}"                                    # boşsa otomatik üretilecek
DATASTREAM_NAME="${DATASTREAM_NAME:-logs-windows-default}"

# Logstash ayar yolları
LS_SETTINGS="/etc/logstash"
LS_KEYSTORE="$LS_SETTINGS/logstash.keystore"

### ======== ÖN KONTROLLER ========
require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "[ERR] '$1' bulunamadı"; exit 1; }; }
require_cmd curl
require_cmd jq || echo "[WARN] 'jq' yok; JSON çıktılar sade gösterilecek."

# CA dosyası yoksa Elasticsearch CA'yı deneyelim
if [[ ! -f "$CA_CERT" ]]; then
  if [[ -f /etc/elasticsearch/certs/ca.crt ]]; then
    CA_CERT="/etc/elasticsearch/certs/ca.crt"
  fi
fi
if [[ ! -f "$CA_CERT" ]]; then
  echo "[ERR] CA sertifikası bulunamadı: $CA_CERT"
  echo "      CA_CERT değişkenini doğru yola işaret edecek şekilde ayarlayın."
  exit 1
fi

if [[ -z "$ELASTIC_PW" ]]; then
  read -s -p "Elastic ($ELASTIC_USER) parolası: " ELASTIC_PW
  echo
fi

# LS_PW yoksa otomatik üret
if [[ -z "$LS_PW" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    LS_PW="$(openssl rand -base64 24)"
  else
    LS_PW="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)"
  fi
  AUTO_GEN=1
else
  AUTO_GEN=0
fi

### ======== FONKSİYONLAR ========
api_put() { # $1 path, $2 json body
  curl -sS -u "$ELASTIC_USER:$ELASTIC_PW" --cacert "$CA_CERT" \
       -H 'Content-Type: application/json' -X PUT "$ES_URL$1" -d "$2"
}
api_post() { # $1 path, $2 json body
  curl -sS -u "$ELASTIC_USER:$ELASTIC_PW" --cacert "$CA_CERT" \
       -H 'Content-Type: application/json' -X POST "$ES_URL$1" -d "$2"
}
api_get() { # $1 path
  curl -sS -u "$ELASTIC_USER:$ELASTIC_PW" --cacert "$CA_CERT" "$ES_URL$1"
}

### ======== ES ULAŞILABİLİYOR MU? ========
echo "[*] Elasticsearch test: $ES_URL"
api_get "/_security/_authenticate" >/dev/null
echo "[OK] Elasticsearch erişimi başarılı."

### ======== ROL: logs-windows-default data stream'e yazma ========
echo "[*] Rol oluştur/yenile: $ROLE_NAME"
ROLE_BODY=$(cat <<JSON
{
  "indices": [
    {
      "names": ["$DATASTREAM_NAME"],
      "privileges": ["auto_configure", "create_doc", "write"]
    }
  ]
}
JSON
)
api_put "/_security/role/$ROLE_NAME" "$ROLE_BODY" >/dev/null
echo "[OK] Rol hazır: $ROLE_NAME (names: [$DATASTREAM_NAME])"

### ======== KULLANICI: logstash_ingest ========
echo "[*] Kullanıcı oluştur/yenile: $LS_USER"
USER_BODY=$(cat <<JSON
{
  "password": "$LS_PW",
  "roles": ["$ROLE_NAME"],
  "enabled": true
}
JSON
)
# Kullanıcıyı PUT ile idempotent oluştur/güncelle
api_put "/_security/user/$LS_USER" "$USER_BODY" >/dev/null
echo "[OK] Kullanıcı hazır: $LS_USER (rol: $ROLE_NAME)"
if [[ "$AUTO_GEN" -eq 1 ]]; then
  echo "[INFO] ${LS_USER} için üretilen parola: $LS_PW"
fi

### ======== LOGSTASH KEYSTORE ========
echo "[*] Logstash keystore hazırlığı: $LS_KEYSTORE"
sudo /usr/share/logstash/bin/logstash-keystore --path.settings "$LS_SETTINGS" create >/dev/null 2>&1 || true

# ES_PW'yi non-interactive eklemek için --stdin kullan
echo -n "$LS_PW" | sudo /usr/share/logstash/bin/logstash-keystore --path.settings "$LS_SETTINGS" add ES_PW --stdin
sudo chown logstash:logstash "$LS_KEYSTORE"
sudo chmod 600 "$LS_KEYSTORE"
echo "[OK] Keystore güncellendi: ES_PW eklendi."

### ======== HIZLI TEST VE SERVİS ========
echo "[*] Logstash config testi:"
sudo /usr/share/logstash/bin/logstash -t --path.settings "$LS_SETTINGS" || { echo "[ERR] Logstash config test FAILED"; exit 1; }

echo "[*] Logstash restart ediliyor..."
sudo systemctl restart logstash

echo "[*] Logstash durum:"
sudo systemctl --no-pager -l status logstash | sed -n '1,12p'

echo "[*] 5045 port dinleme kontrolü:"
sudo ss -ltnp | grep -E ':(5045)\b' || echo "[WARN] 5045 görünmüyor; beats input conf'unu kontrol edin."

echo "[DONE] İşlem tamam."
