#!/usr/bin/env bash
# HomoLock-HR end-to-end demo.
# Run from repo root. Requires: cmake, g++, libcurl, Python 3.10+, SEAL (via FetchContent).

set -e
export HOMOLOCK_WORKER=""
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

echo "=== HomoLock-HR Demo ==="

# Directories
mkdir -p out data
SERVER_URL="${SERVER_URL:-http://127.0.0.1:8000}"

# Build C++ worker (server_py/cpp_worker)
echo "[1/3] Building C++ worker..."
WORKER_DIR="$REPO_ROOT/server_py/cpp_worker"
mkdir -p "$WORKER_DIR/build"
cd "$WORKER_DIR/build"
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build . -j
export HOMOLOCK_WORKER="$WORKER_DIR/build/homolock_worker"
cd "$REPO_ROOT"
echo "  Worker: $HOMOLOCK_WORKER"

# Build C++ client (client_cpp)
echo "[2/3] Building C++ client..."
CLIENT_DIR="$REPO_ROOT/client_cpp"
mkdir -p "$CLIENT_DIR/build"
cd "$CLIENT_DIR/build"
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build . -j
CLIENT_BIN="$CLIENT_DIR/build/homolock_client"
cd "$REPO_ROOT"
echo "  Client: $CLIENT_BIN"

# Install Python deps if needed
if ! python3 -c "import fastapi" 2>/dev/null; then
  echo "Installing server Python deps..."
  pip install -r server_py/requirements.txt
fi

# Start server in background
echo "[3/3] Starting FastAPI server on 127.0.0.1:8000..."
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

# Wait for health
for i in 1 2 3 4 5; do
  if curl -s "$SERVER_URL/health" | grep -q '"status":"ok"'; then break; fi
  sleep 1
done
curl -s "$SERVER_URL/health" && echo ""

# Client steps
SESSION_ID="demo-$(date +%s)"
echo ""
echo "=== Client: init-context ==="
"$CLIENT_BIN" init-context --poly 8192

echo ""
echo "=== Client: keygen ==="
"$CLIENT_BIN" keygen

echo ""
echo "=== Client: encrypt-hr ==="
"$CLIENT_BIN" encrypt-hr

echo ""
echo "=== Client: upload-session ==="
"$CLIENT_BIN" upload-session --server "$SERVER_URL" --session "$SESSION_ID"

echo ""
echo "=== Client: upload-data ==="
"$CLIENT_BIN" upload-data --server "$SERVER_URL" --session "$SESSION_ID"

echo ""
echo "=== Client: compute (total_payroll, avg_salary, total_hours, bonus_pool) ==="
COMPUTE_OUT=$("$CLIENT_BIN" compute --server "$SERVER_URL" --session "$SESSION_ID" --bonus-bps 1000)
echo "$COMPUTE_OUT"
JOB_PAYROLL=$(echo "$COMPUTE_OUT" | grep "total_payroll job_id=" | sed 's/.*job_id=//')
JOB_AVG=$(echo "$COMPUTE_OUT" | grep "avg_salary job_id=" | sed 's/.*job_id=//')
JOB_HOURS=$(echo "$COMPUTE_OUT" | grep "total_hours job_id=" | sed 's/.*job_id=//')
JOB_BONUS=$(echo "$COMPUTE_OUT" | grep "bonus_pool job_id=" | sed 's/.*job_id=//')

echo ""
echo "=== Fetch and decrypt results ==="
for label in "Total payroll:total_payroll:$JOB_PAYROLL" "Avg salary:avg_salary:$JOB_AVG" "Total hours:total_hours:$JOB_HOURS" "Bonus pool (sum):bonus_pool:$JOB_BONUS"; do
  IFS=: read -r title _ job_id <<< "$label"
  if [ -n "$job_id" ]; then
    echo "--- $title ---"
    "$CLIENT_BIN" fetch-and-decrypt --server "$SERVER_URL" --job-id "$job_id"
    echo ""
  fi
done

echo "=== Demo complete ==="
