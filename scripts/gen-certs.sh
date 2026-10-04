#!/usr/bin/env bash
# Generates the real X.509 certificates embedded in the demo PCAP captures.
set -e
OUT=scripts/certs
mkdir -p "$OUT"; cd "$OUT"
export MSYS_NO_PATHCONV=1

# Trusted internal CA + healthy mail server certificate (RSA-2048 / SHA-256)
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 3650 -sha256 \
  -subj "/C=IN/O=Acme Corp/CN=Acme Corp Issuing CA G2" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout mail.key -out mail.csr \
  -subj "/C=IN/O=Acme Corp/CN=mail.acme-corp.in" 2>/dev/null
printf "subjectAltName=DNS:mail.acme-corp.in,DNS:smtp.acme-corp.in,DNS:imap.acme-corp.in\n" > san.ext
openssl x509 -req -in mail.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out mail.pem -days 397 -sha256 -extfile san.ext 2>/dev/null

# ECDSA P-256 certificate for the IMAPS server
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout imap.key -out imap.csr \
  -subj "/C=IN/O=Acme Corp/CN=imap.acme-corp.in" 2>/dev/null
openssl x509 -req -in imap.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out imap.pem -days 397 -sha256 2>/dev/null

# Legacy POP3 server: RSA-1024, SHA-1, self-signed, already expired
openssl req -x509 -newkey rsa:1024 -nodes -keyout legacy.key -out legacy.pem -sha1 \
  -subj "/C=IN/O=Acme Legacy/CN=pop.legacy.acme-corp.in" \
  -not_before 20210101000000Z -not_after 20240101000000Z 2>/dev/null

# Rogue interception cert: same CN as the real server, different (untrusted) issuer
openssl req -x509 -newkey rsa:2048 -nodes -keyout rogue-ca.key -out rogue-ca.pem -days 365 -sha256 \
  -subj "/C=US/O=NetFilter Gateway/CN=NetFilter Inspection CA" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout rogue.key -out rogue.csr \
  -subj "/C=IN/O=Acme Corp/CN=mail.acme-corp.in" 2>/dev/null
openssl x509 -req -in rogue.csr -CA rogue-ca.pem -CAkey rogue-ca.key -CAcreateserial -out rogue.pem -days 30 -sha256 2>/dev/null

for f in ca mail imap legacy rogue-ca rogue; do openssl x509 -in $f.pem -outform DER -out $f.der; done
rm -f *.key *.csr *.srl san.ext
echo "certs generated"
