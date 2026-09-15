#!/usr/bin/env bash
set -e
set -o pipefail

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
until docker compose exec -T backend curl -s -f "$HEALTH_URL" >/dev/null 2>&1; do
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
