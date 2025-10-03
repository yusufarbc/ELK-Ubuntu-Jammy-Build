#!/usr/bin/env bash
# tools/generate-self-signed-certs.sh
# Basit CA + sertifika üretimi scripti. Test / lab amaçlıdır.

set -euo pipefail

OUTDIR="$(dirname "$0")/../certs"
mkdir -p "$OUTDIR"
cd "$OUTDIR"

# Varsayılan CN ve SAN'ları ayarlayın (gerekirse düzenleyin)
HOSTNAME=${HOSTNAME:-localhost}
IP_ADDR=${IP_ADDR:-127.0.0.1}

echo "Üretim için lütfen geçerli CA ve sertifikalar kullanın. Bu script test amaçlı self-signed sertifika üretir."

# Create CA key and cert
if [ ! -f "ca.key.pem" ] || [ ! -f "ca.cert.pem" ]; then
  echo "Creating CA key and cert..."
  openssl genrsa -out ca.key.pem 4096
  openssl req -x509 -new -nodes -key ca.key.pem -sha256 -days 3650 -out ca.cert.pem -subj "/C=TR/ST=Istanbul/L=Istanbul/O=SIEM Lab/OU=CA/CN=siem-lab-ca"
else
  echo "CA already exists, skipping"
fi

# function to create a cert with SAN
create_cert() {
  name="$1"
  cn="$2"
  san="$3"

  keyfile="${name}.key.pem"
  csrfile="${name}.csr.pem"
  certfile="${name}.cert.pem"
  extfile="${name}_ext.cnf"

  if [ -f "$certfile" ]; then
    echo "Certificate $certfile exists, skipping"
    return
  fi

  echo "Generating key and CSR for $name (CN=$cn)..."
  openssl genrsa -out "$keyfile" 2048
  openssl req -new -key "$keyfile" -out "$csrfile" -subj "/C=TR/ST=Istanbul/L=Istanbul/O=SIEM Lab/OU=Services/CN=${cn}"

  cat > "$extfile" <<EOF
[ v3_req ]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${cn}
DNS.2 = localhost
IP.1 = ${IP_ADDR}
EOF

  echo "Signing certificate for $name..."
  openssl x509 -req -in "$csrfile" -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial -out "$certfile" -days 365 -sha256 -extfile "$extfile" -extensions v3_req

  # tighten permissions
  chmod 0400 "$keyfile"
  chmod 0444 "$certfile"
  rm -f "$csrfile" "$extfile"
  echo "Created $certfile and $keyfile"
}

create_cert elasticsearch "elasticsearch" "$HOSTNAME"
create_cert kibana "kibana" "$HOSTNAME"
create_cert logstash "logstash" "$HOSTNAME"

# Also create a combined PEM for elasticsearch HTTP layer if needed
if [ ! -f "elasticsearch-http-combined.pem" ]; then
  echo "Creating combined PEM for elasticsearch (key+cert)..."
  cat elasticsearch.key.pem elasticsearch.cert.pem > elasticsearch-http-combined.pem
  chmod 0440 elasticsearch-http-combined.pem
fi

echo "Sertifikalar üretildi: $OUTDIR"

echo "Örnek kullanım:
  HOSTNAME=siem.example.com IP_ADDR=10.0.0.5 bash tools/generate-self-signed-certs.sh
Sonrasında docker-compose up -d çalıştırabilirsiniz."
