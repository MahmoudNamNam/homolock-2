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
  echo "  PySEAL (seal) not found. Install it for encrypt/decrypt (e.g. Huelse/SEAL-Python)."
  echo "  Demo will start server and show CRUD; compute will fail without seal on server."
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

# Python client: run from repo root so out/ and data/ are here
export PYTHONPATH="$REPO_ROOT/server_py:$PYTHONPATH"
CLI="python3 -m client.cli"
cd "$REPO_ROOT"

SESSION_ID="demo-$(date +%s)"
echo ""
echo "=== Client: init-context ==="
$CLI init-context --poly 8192 || { echo "  (install PySEAL for init-context)"; exit 0; }

echo ""
echo "=== Client: keygen ==="
$CLI keygen || true

echo ""
echo "=== Client: encrypt-hr ==="
$CLI encrypt-hr || true

echo ""
echo "=== Client: upload-session ==="
$CLI upload-session --server "$SERVER_URL" --session-id "$SESSION_ID" || true

echo ""
echo "=== Client: upload-data ==="
$CLI upload-data --session-id "$SESSION_ID" --server "$SERVER_URL" || true

echo ""
echo "=== Client: compute ==="
COMPUTE_OUT=$($CLI compute --session-id "$SESSION_ID" --server "$SERVER_URL" --bonus-bps 1000 2>/dev/null) || true
echo "$COMPUTE_OUT"
JOB_PAYROLL=$(echo "$COMPUTE_OUT" | grep "total_payroll" | sed 's/.*job_id=//')
JOB_AVG=$(echo "$COMPUTE_OUT" | grep "avg_salary" | sed 's/.*job_id=//')
JOB_HOURS=$(echo "$COMPUTE_OUT" | grep "total_hours" | sed 's/.*job_id=//')
JOB_BONUS=$(echo "$COMPUTE_OUT" | grep "bonus_pool" | sed 's/.*job_id=//')

echo ""
echo "=== Fetch and decrypt results ==="
for label in "Total payroll:$JOB_PAYROLL" "Avg salary:$JOB_AVG" "Total hours:$JOB_HOURS" "Bonus pool:$JOB_BONUS"; do
  IFS=: read -r title job_id <<< "$label"
  if [ -n "$job_id" ]; then
    echo "--- $title ---"
    $CLI fetch-decrypt --server "$SERVER_URL" --job-id "$job_id" 2>/dev/null || echo "  (decrypt requires PySEAL)"
    echo ""
  fi
done

echo "=== Optional: CRUD employees ==="
echo "  (from repo root) PYTHONPATH=$REPO_ROOT/server_py $CLI employee create --session-id $SESSION_ID --employee-id 1001 --from-csv"
echo "  PYTHONPATH=$REPO_ROOT/server_py $CLI employee list --session-id $SESSION_ID"
echo ""
echo "=== Demo complete ==="
