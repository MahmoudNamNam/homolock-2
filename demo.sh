#!/usr/bin/env bash
# HomoLock-HR end-to-end demo (Python only).
# Run from repo root. Requires: Python 3.10+, pip, PySEAL (seal package).

set -e
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

echo "=== HomoLock-HR Demo (Python) ==="

mkdir -p out data
SERVER_URL="${SERVER_URL:-http://127.0.0.1:8000}"

# Python deps (server + client)
echo "[1/2] Installing Python deps..."
pip install -q -r server_py/requirements.txt
if ! python3 -c "import seal" 2>/dev/null; then
  echo "  PySEAL (seal) not found. Try: pip install seal (or build from source, e.g. Huelse/SEAL-Python)."
  echo "  Demo will start server; run will fail without seal on client and server."
fi

# Start server in background
echo "[2/2] Starting FastAPI server on 127.0.0.1:8000..."
cd server_py
uvicorn app.main:app --host 127.0.0.1 --port 8000 &
SERVER_PID=$!
cd "$REPO_ROOT"
sleep 2
if ! kill -0 $SERVER_PID 2>/dev/null; then
  echo "Server failed to start."
  exit 1
fi
trap "kill $SERVER_PID 2>/dev/null || true" EXIT

for i in 1 2 3 4 5; do
  if curl -s "$SERVER_URL/health" | grep -q '"status":"ok"'; then break; fi
  sleep 1
done
curl -s "$SERVER_URL/health" && echo ""

# One-command flow: init → keygen → encrypt → upload → compute → fetch-decrypt
export PYTHONPATH="$REPO_ROOT/server_py:$PYTHONPATH"
echo ""
python3 -m client.cli run --server "$SERVER_URL" || true

echo ""
echo "=== Demo complete ==="
