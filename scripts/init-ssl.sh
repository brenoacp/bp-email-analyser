#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." >/dev/null 2>&1 && pwd )"
cd "$DIR"

if [ ! -f .env ]; then
    echo "[-] Erro: Arquivo .env não encontrado! Copie de .env.production.example e configure seu DOMAIN e LETSENCRYPT_EMAIL."
    exit 1
fi

source .env

if [ -z "$DOMAIN" ] || [ "$DOMAIN" = "localhost" ] || [ "$DOMAIN" = "email-analyzer.seudominio.com.br" ]; then
    echo "[-] Erro: A variável DOMAIN no .env precisa ser configurada com um domínio público válido (ex: analisador.meudominio.com)."
    exit 1
fi

if [ -z "$LETSENCRYPT_EMAIL" ] || [ "$LETSENCRYPT_EMAIL" = "admin@seudominio.com.br" ]; then
    echo "[-] Erro: A variável LETSENCRYPT_EMAIL precisa ser preenchida com um e-mail válido para avisos de expiração."
    exit 1
fi

CERT_PATH="./certbot/conf/live/$DOMAIN"

mkdir -p "./certbot/conf/live/$DOMAIN"
mkdir -p "./certbot/www"

if [ -d "$CERT_PATH" ] && [ -f "$CERT_PATH/fullchain.pem" ]; then
    read -r -p "[?] Certificado existente encontrado para $DOMAIN. Deseja substituí-lo? (s/N) " DECISION
    if [ "$DECISION" != "s" ] && [ "$DECISION" != "S" ]; then
        echo "[*] Abortando bootstrap de SSL. Certificado mantido."
        exit 0
    fi
fi

echo "[+] 1/4 - Criando certificado autoassinado temporário para permitir a inicialização do Nginx..."
openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
    -keyout "$CERT_PATH/privkey.pem" \
    -out "$CERT_PATH/fullchain.pem" \
    -subj "/CN=localhost" 2>/dev/null

echo "[+] 2/4 - Subindo contêiner Nginx..."
docker compose up -d web

echo "[+] 3/4 - Removendo certificado temporário e solicitando certificado oficial via Let's Encrypt..."
rm -rf "$CERT_PATH"

STAGING_ARG=""
if [ "${CERTBOT_STAGING:-0}" != "0" ]; then
    echo "[!] ATENÇÃO: Executando em modo STAGING do Let's Encrypt (teste)."
    STAGING_ARG="--staging"
fi

docker compose run --rm --entrypoint certbot certbot certonly \
    --webroot \
    -w /var/www/certbot \
    $STAGING_ARG \
    -d "$DOMAIN" \
    --email "$LETSENCRYPT_EMAIL" \
    --rsa-key-size 4096 \
    --agree-tos \
    --force-renewal \
    --non-interactive

echo "[+] 4/4 - Recarregando o Nginx com o novo certificado..."
docker compose exec -T web nginx -s reload

echo "=== SSL configurado com sucesso para https://$DOMAIN ==="
