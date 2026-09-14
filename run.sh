#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "=== Inicializando bp-email-analiser ==="

# 1. Setup Python Venv
if [ ! -d "backend/.venv" ]; then
    echo "[+] Criando virtualenv Python..."
    python3 -m venv backend/.venv
    backend/.venv/bin/pip install --upgrade pip
    backend/.venv/bin/pip install -r backend/requirements.txt
fi

# 2. Build Frontend se dist não existir
if [ ! -d "frontend/dist" ]; then
    echo "[+] Instalando dependências e buildando frontend..."
    cd frontend && npm install && npm run build && cd ..
fi

# 3. Inicializar Servidores
echo "[+] Iniciando Backend FastAPI na porta 8000..."
backend/.venv/bin/uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

echo "[+] Iniciando Frontend na porta 5173..."
cd frontend && npx vite --host 0.0.0.0 --port 5173 &
FRONTEND_PID=$!

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true" EXIT INT TERM

echo "=== bp-email-analiser ativo! ==="
echo "Frontend: http://localhost:5173"
echo "API Docs: http://localhost:8000/docs"
wait
