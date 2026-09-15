# Deploy em Produção (Docker + Nginx + Certbot) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Empacotar e configurar a infraestrutura de deploy do BP Email Header Analyzer (`bp-email-analiser`) utilizando Docker, Docker Compose, Nginx com renovação automática de SSL (Certbot Let's Encrypt), volumes persistentes para auditoria forense e script automatizado de deploy (`deploy.sh`).

**Architecture:** A aplicação é orquestrada em contêineres: um contêiner `backend` (FastAPI / Python 3.12-slim) com healthcheck e persistência de `./logs`, um contêiner `web` (Nginx Alpine) servindo a SPA do frontend compilada e atuando como proxy reverso para `/api/`, e um contêiner auxiliar `certbot` para emissão e renovação automática de certificados TLS via desafio webroot.

**Tech Stack:** Docker, Docker Compose v2, Nginx 1.27 Alpine, Certbot (EFF Let's Encrypt), Python 3.12-slim, Node.js 20 Alpine, Bash.

**Spec:** `docs/superpowers/specs/2026-09-15-server-deploy-design.md`

## Global Constraints

- **SO Alvo**: Linux (Ubuntu/Debian ou distribuição moderna com Docker Engine e Docker Compose v2 instalados).
- **Portas Públicas**: Apenas `80/tcp` (HTTP) e `443/tcp` (HTTPS) devem ser expostas no host. A porta `8000` do backend permanece privada na rede interna Docker (`bp-network`).
- **Persistência de Logs**: O diretório `./logs` do host deve ser montado em `/app/logs` do backend para garantir que `audit.log` sobreviva a restarts.
- **Roteamento SPA**: O Nginx deve ter fallback `try_files $uri $uri/ /index.html;` para permitir rotas no cliente React.
- **Zero Downtime / Idempotência**: O script `deploy.sh` deve validar pré-requisitos, atualizar o código, subir novas versões e validar `/api/health` antes de encerrar.

---

### Task 1: Backend Dockerfile e `.dockerignore`

**Files:**
- Create: `backend/.dockerignore`
- Create: `backend/Dockerfile`
- Test: Build da imagem Docker do backend e teste do healthcheck

**Interfaces:**
- Consumes: `backend/requirements.txt`, `backend/app/main.py`
- Produces: Imagem `bp-backend:test` expondo porta 8000 internamente com healthcheck em `/api/health`

- [ ] **Step 1: Criar o arquivo `backend/.dockerignore`**

```dockerignore
__pycache__
*.pyc
*.pyo
*.pyd
.Python
.pytest_cache
.coverage
htmlcov
.venv
venv
ENV
logs/*.log
.git
.gitignore
```

- [ ] **Step 2: Criar o arquivo `backend/Dockerfile`**

```dockerfile
FROM python:3.12-slim AS runtime

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Instala curl para permitir o healthcheck do contêiner
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Copia e instala as dependências Python
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copia o código-fonte da aplicação
COPY app/ ./app/

# Cria o diretório para armazenamento dos logs forenses
RUN mkdir -p /app/logs

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--proxy-headers"]
```

- [ ] **Step 3: Testar o build da imagem do backend**

Run: `docker build -t bp-backend:test ./backend`
Expected: Build concluído com sucesso gerando a tag `bp-backend:test`.

- [ ] **Step 4: Executar contêiner de teste do backend e validar `/api/health`**

Run:
```bash
docker run -d --name bp-backend-check -p 8009:8000 bp-backend:test
sleep 3
curl -s http://localhost:8009/api/health
docker rm -f bp-backend-check
```
Expected: Retorno JSON contendo `{"status":"healthy","service":"bp-email-analiser"}`.

- [ ] **Step 5: Commit das alterações do backend**

Run:
```bash
git add backend/.dockerignore backend/Dockerfile
git commit -m "feat(docker): add backend dockerfile and dockerignore with healthcheck"
```

---

### Task 2: Configurações Nginx e Frontend Dockerfile Multi-Stage

**Files:**
- Create: `frontend/.dockerignore`
- Create: `docker/nginx/nginx.conf`
- Create: `docker/nginx/templates/default.conf.template`
- Create: `frontend/Dockerfile`
- Test: Build multi-stage da imagem web e validação dos estáticos e sintaxe do Nginx

**Interfaces:**
- Consumes: `frontend/package.json`, `frontend/src/`, `frontend/index.html`
- Produces: Imagem `bp-web:test` contendo os estáticos do frontend e configuração de proxy reverso Nginx

- [ ] **Step 1: Criar o arquivo `frontend/.dockerignore`**

```dockerignore
node_modules
dist
.git
.gitignore
*.log
.vscode
.idea
```

- [ ] **Step 2: Criar o arquivo `docker/nginx/nginx.conf`**

```nginx
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    gzip on;
    gzip_disable "msie6";
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript image/svg+xml;

    include /etc/nginx/conf.d/*.conf;
}
```

- [ ] **Step 3: Criar o template do VirtualHost `docker/nginx/templates/default.conf.template`**

```nginx
# Redirecionamento HTTP -> HTTPS e desafio ACME Certbot
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

# Servidor HTTPS Seguro
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name ${DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";

    # Cabeçalhos de Segurança
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    root /usr/share/nginx/html;
    index index.html;
    client_max_body_size 10M;

    # Roteamento Frontend SPA
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache de Assets Estáticos do Vite
    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Proxy Reverso para a API FastAPI
    location /api/ {
        proxy_pass http://backend:8000/api/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
        proxy_connect_timeout 10s;
    }
}
```

- [ ] **Step 4: Criar o arquivo `frontend/Dockerfile`**

```dockerfile
# Stage 1: Build do Frontend com Node
FROM node:20-alpine AS builder

WORKDIR /app

COPY frontend/package.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# Stage 2: Runtime Nginx
FROM nginx:1.27-alpine AS runtime

# Remove configuração padrão
RUN rm /etc/nginx/conf.d/default.conf

# Copia arquivo principal de configuração
COPY docker/nginx/nginx.conf /etc/nginx/nginx.conf

# Copia o template que utilizará envsubst para substituir ${DOMAIN}
COPY docker/nginx/templates/default.conf.template /etc/nginx/templates/default.conf.template

# Copia os arquivos compilados da SPA
COPY --from=builder /app/dist /usr/share/nginx/html

# Cria diretório para desafio do Certbot
RUN mkdir -p /var/www/certbot

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
```

- [ ] **Step 5: Testar o build da imagem web**

Run: `docker build -t bp-web:test -f ./frontend/Dockerfile .`
Expected: Build concluído com sucesso e tag `bp-web:test` gerada.

- [ ] **Step 6: Commit das configurações do Nginx e Dockerfile do frontend**

Run:
```bash
git add frontend/.dockerignore docker/ frontend/Dockerfile
git commit -m "feat(docker): add frontend multi-stage dockerfile and nginx templates"
```

---

### Task 3: Configuração do Ambiente e Orquestração Docker Compose

**Files:**
- Create: `.env.production.example`
- Create: `docker-compose.yml`
- Test: Validação de sintaxe e renderização com `docker compose config`

**Interfaces:**
- Consumes: `backend/Dockerfile`, `frontend/Dockerfile`, `.env`
- Produces: Pilha orquestrada com `backend`, `web` e `certbot` sob rede `bp-network`

- [ ] **Step 1: Criar o arquivo `.env.production.example`**

```ini
# ==============================================================================
# BP Email Header Analyzer - Configurações de Produção (.env)
# ==============================================================================

# --- Domínio e Certificados SSL (Let's Encrypt) ---
DOMAIN=email-analyzer.seudominio.com.br
LETSENCRYPT_EMAIL=admin@seudominio.com.br
CERTBOT_STAGING=0

# --- Aplicação FastAPI ---
PROJECT_NAME="bp-email-analiser"
API_PREFIX="/api"
NETWORK_TIMEOUT_SECONDS=2.5
MAX_HEADER_SIZE_BYTES=1000000

# --- Auditoria Forense e Logs ---
AUDIT_LOG_ENABLED=True
AUDIT_LOG_LEVEL="FULL"
AUDIT_LOG_FILE="logs/audit.log"
AUDIT_LOG_MAX_BYTES=10485760
AUDIT_LOG_BACKUP_COUNT=5
AUDIT_LOG_STDOUT=True
```

- [ ] **Step 2: Criar o arquivo `docker-compose.yml`**

```yaml
version: '3.8'

services:
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: bp-backend
    restart: unless-stopped
    env_file:
      - .env
    volumes:
      - ./logs:/app/logs
    networks:
      - bp-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/health"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 10s

  web:
    build:
      context: .
      dockerfile: ./frontend/Dockerfile
    container_name: bp-web
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    environment:
      - DOMAIN=${DOMAIN:-localhost}
    volumes:
      - ./certbot/conf:/etc/letsencrypt:ro
      - ./certbot/www:/var/www/certbot:ro
    depends_on:
      backend:
        condition: service_healthy
    networks:
      - bp-network

  certbot:
    image: certbot/certbot:latest
    container_name: bp-certbot
    restart: unless-stopped
    volumes:
      - ./certbot/conf:/etc/letsencrypt
      - ./certbot/www:/var/www/certbot
    entrypoint: >
      sh -c "trap exit TERM; while :; do certbot renew --webroot -w /var/www/certbot --quiet; sleep 12h & wait $${!}; done;"
    networks:
      - bp-network

networks:
  bp-network:
    driver: bridge
```

- [ ] **Step 3: Validar a sintaxe do Compose**

Run: `DOMAIN=localhost docker compose -f docker-compose.yml config`
Expected: Exibe a configuração compilada sem erros de parsing YAML ou dependências.

- [ ] **Step 4: Commit do arquivo docker-compose.yml e .env.production.example**

Run:
```bash
git add .env.production.example docker-compose.yml
git commit -m "feat(docker): add production docker-compose.yml and .env.production.example"
```

---

### Task 4: Script de Bootstrap SSL com Certbot (`scripts/init-ssl.sh`)

**Files:**
- Create: `scripts/init-ssl.sh`
- Test: Teste de execução em modo de validação de sintaxe e permissões (`chmod +x`)

**Interfaces:**
- Consumes: `.env` (`DOMAIN`, `LETSENCRYPT_EMAIL`, `CERTBOT_STAGING`), `docker-compose.yml`
- Produces: Geração de certificado inicial dummy, subida do Nginx, requisição do certificado oficial Let's Encrypt e reload

- [ ] **Step 1: Criar o script `scripts/init-ssl.sh`**

```bash
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
    read -p "[?] Certificado existente encontrado para $DOMAIN. Deseja substituí-lo? (s/N) " DECISION
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

docker compose run --rm certbot certonly \
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
docker compose exec web nginx -s reload

echo "=== SSL configurado com sucesso para https://$DOMAIN ==="
```

- [ ] **Step 2: Tornar o script executável e testar a sintaxe**

Run:
```bash
chmod +x scripts/init-ssl.sh
bash -n scripts/init-ssl.sh
```
Expected: Nenhum erro de sintaxe bash retornado (código de saída 0).

- [ ] **Step 3: Commit do script `scripts/init-ssl.sh`**

Run:
```bash
git add scripts/init-ssl.sh
git commit -m "feat(deploy): add ssl bootstrap script with dummy certificate fallback"
```

---

### Task 5: Script Idempotente de Deploy em Produção (`deploy.sh`)

**Files:**
- Create: `deploy.sh`
- Test: Validação de sintaxe bash e teste de flags / checagem de pré-requisitos

**Interfaces:**
- Consumes: `.env`, `docker-compose.yml`, git repo
- Produces: Execução limpa do fluxo de deploy: validação, `git pull`, `build`, `up -d`, polling de healthcheck e limpeza

- [ ] **Step 1: Criar o script `deploy.sh`**

```bash
#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "========================================================"
echo "  BP Email Header Analyzer - Deploy em Produção"
echo "========================================================"

# 1. Validação de Ferramentas
command -v docker >/dev/null 2>&1 || { echo "[-] Erro: Docker não está instalado no servidor."; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "[-] Erro: Docker Compose v2 não está instalado ou habilitado."; exit 1; }

# 2. Validação do Arquivo .env
if [ ! -f .env ]; then
    echo "[-] Erro: Arquivo .env não encontrado no diretório do projeto."
    echo "[!] Crie o arquivo a partir de .env.production.example:"
    echo "    cp .env.production.example .env && nano .env"
    exit 1
fi

# 3. Garantir existência e permissões do diretório de logs
mkdir -p logs
chmod 755 logs

# 4. Atualização do repositório (Git Pull) se estiver em um repositório git com upstream configurado
if [ -d .git ]; then
    echo "[+] Sincronizando código com o repositório remoto..."
    git pull --ff-only || {
        echo "[!] Aviso: Falha no git pull rápido. Continuando com o código local..."
    }
fi

# 5. Build e Subida dos Serviços
echo "[+] Construindo imagens atualizadas..."
docker compose build --pull

echo "[+] Inicializando serviços em segundo plano..."
docker compose up -d --remove-orphans

# 6. Verificação de Saúde (Healthcheck)
echo "[+] Aguardando inicialização e verificando saúde da API..."
MAX_ATTEMPTS=15
ATTEMPT=1
HEALTH_URL="http://localhost:8000/api/health"

# Permite verificar via container caso a porta 8000 do host não esteja exposta
until docker compose exec -T backend curl -s -f http://localhost:8000/api/health >/dev/null 2>&1; do
    if [ "$ATTEMPT" -ge "$MAX_ATTEMPTS" ]; then
        echo "[-] ERRO: A aplicação não respondeu com status saudável após $MAX_ATTEMPTS tentativas."
        echo "[-] Últimos logs do backend:"
        docker compose logs --tail=50 backend
        exit 1
    fi
    echo "    [Tentativa $ATTEMPT/$MAX_ATTEMPTS] Aguardando backend responder..."
    sleep 2
    ATTEMPT=$((ATTEMPT + 1))
done

echo "[+] Backend saudável e respondendo com sucesso!"

# 7. Limpeza de imagens antigas não utilizadas
echo "[+] Limpando imagens Docker órfãs..."
docker image prune -f >/dev/null 2>&1 || true

echo "========================================================"
echo "  Deploy finalizado com sucesso! 🚀"
echo "  Status dos serviços:"
echo "========================================================"
docker compose ps
```

- [ ] **Step 2: Tornar o script executável e testar a sintaxe**

Run:
```bash
chmod +x deploy.sh
bash -n deploy.sh
```
Expected: Nenhum erro de sintaxe bash retornado (código de saída 0).

- [ ] **Step 3: Commit do script `deploy.sh`**

Run:
```bash
git add deploy.sh
git commit -m "feat(deploy): add automated production deploy script with healthcheck and validation"
```

---

### Task 6: Documentação de Deploy e Instruções Operacionais no `README.md`

**Files:**
- Modify: `README.md`
- Test: Verificação de links e instruções do guia de deploy

**Interfaces:**
- Consumes: Informações consolidadas de deploy das tarefas 1 a 5
- Produces: Seção detalhada e clara no `README.md` cobrindo pré-requisitos, primeiro deploy, renovação SSL e manutenção

- [ ] **Step 1: Adicionar seção "Deploy em Produção" no `README.md`**

Adicionar as seguintes instruções estruturadas no `README.md`:
1. **Requisitos de Sistema**: Ubuntu 22.04/24.04 ou Debian, Docker Engine e Docker Compose v2, Portas 80 e 443 abertas no firewall (UFW/Security Group).
2. **Guia de Instalação Passo a Passo**:
   - Clonagem do repositório no servidor.
   - Configuração do `.env` a partir de `.env.production.example`.
   - Execução de `./scripts/init-ssl.sh` para o primeiro certificado.
   - Execução de `./deploy.sh` para deploy regular.
3. **Comandos Úteis de Operação**:
   - Como monitorar logs forenses (`tail -f logs/audit.log`).
   - Como visualizar status dos contêineres (`docker compose ps`).
   - Como reiniciar serviços (`docker compose restart`).

- [ ] **Step 2: Verificar a formatação e consistência do `README.md`**

Run: `git diff README.md`
Expected: Diff limpo com a nova seção de deploy sem alterar outras seções vigentes.

- [ ] **Step 3: Commit das alterações na documentação**

Run:
```bash
git add README.md
git commit -m "docs: add production deployment guide with docker and letsencrypt to README"
```

---

## Self-Review do Plano

- **Spec Coverage**:
  - Dockerfile Backend (Python 3.12-slim, healthcheck, logs) -> Coberto na **Task 1**.
  - Dockerfile Frontend & Nginx (Multi-stage, templates, gzip, headers) -> Coberto na **Task 2**.
  - Docker Compose & Variáveis (.env.production.example, bp-network, certbot) -> Coberto na **Task 3**.
  - Bootstrap SSL inicial (`scripts/init-ssl.sh`) -> Coberto na **Task 4**.
  - Script de deploy automatizado (`deploy.sh`) -> Coberto na **Task 5**.
  - Documentação operacional -> Coberto na **Task 6**.
- **Placeholder Scan**: Não há termos como TBD, TODO ou etapas genéricas sem código. Todos os comandos, arquivos e scripts contêm o código completo.
- **Type Consistency**: Os nomes de serviços (`backend`, `web`, `certbot`), diretórios (`./logs`, `./certbot/conf`, `./certbot/www`) e variáveis (`DOMAIN`, `LETSENCRYPT_EMAIL`, `CERTBOT_STAGING`) estão 100% alinhados entre todos os arquivos.
