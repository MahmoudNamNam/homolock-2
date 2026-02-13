# Postman – HomoLock-HR API

## Using a deployed server (e.g. AWS)

If the API is deployed on AWS (or any host), set the collection variable **`base_url`** to that URL:

- **EC2 (no HTTPS):** `http://<EC2_PUBLIC_IP>:8000`
- **With domain + HTTPS:** `https://your-domain.com`

Then run the same requests; no other changes needed. See **`server_py/docs/DEPLOY-AWS.md`** for full deploy steps and usage (CLI, cURL, one-shot run).

---

## Import the collection

1. Open **Postman**.
2. **Import** → **Upload Files** → select `HomoLock-HR.postman_collection.json` (in this folder).
3. The collection **HomoLock-HR** appears with variables: `base_url` (default `http://localhost:8000`), `session_id`, `job_id_*`, `employee_id`.

---

## Session Keys / Session Data (endpoints only, no CLI)

The payloads are too large for Postman's pre-request script (you'd get "Maximum response size reached"). Use this flow instead:

1. **Server** must have static data (run once: `python -m scripts.generate_static_data` in `server_py/`).

2. **In Postman** → **2 - Session**:
   - Run **Get Session Keys (body)** — GET `{{base_url}}/v1/static/session-keys?session_id={{session_id}}`. Copy the **entire response body**.
   - Open **Session Keys** (POST). Paste the copied JSON into the Body. Click **Send**.
   - Same for data: run **Get Session Data (body)**, copy response, paste into **Session Data** (POST), **Send**.

All via endpoints; no CLI.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/static/session-keys?session_id=...` | Response = body for POST /v1/session/keys (copy & paste) |
| GET | `/v1/static/session-data?session_id=...` | Response = body for POST /v1/session/data (copy & paste) |

**"Maximum response size reached" on Get Session Keys/Data?** The server now compresses large responses (gzip). If your client still hits a size limit, use **curl** and save to a file, then paste into the POST body: `curl -s -H "Accept-Encoding: gzip" "http://localhost:8000/v1/static/session-keys?session_id=my-session" -o keys.json` then copy contents of `keys.json` into Session Keys body.

**Why is GET .../employees empty?** Batch upload (Run All or session/data) does not add per-employee entries. Call **POST** `/v1/session/{session_id}/employees/from-batch` after Run All or session/data; optional body `{"employee_ids": ["1001", "1002", ...]}` (order = batch/CSV order). Then GET .../employees returns those ids.

---

## Run the server

```bash
cd server_py
# Optional: generate static data once
python -m scripts.generate_static_data
# Start server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

---

## How to run all endpoints

### Option A: Postman – “Run all” with static data (easiest)

1. Start the server (see above). Ensure static data exists: `server_py/static/` has `params.seal`, `public_key.seal`, `relin_keys.seal`, `salary.ct`, `hours.ct`, `bonus_points.ct`, `meta.json` (run `python -m scripts.generate_static_data` once).
2. In Postman, open the collection **HomoLock-HR**.
3. Open folder **1 - Quick flow (static)**.
4. Click **Run** (Collection Runner).
5. Select **1 - Quick flow (static)** and run. Order:
   - **Health** → `GET /health`
   - **Run All (static data)** → `POST /v1/run` with body `{}`; the Test script saves `session_id` and all `job_id_*` into collection variables.
   - **Get Result - total_payroll** … **Get Result - bonus_pool** → each `GET /v1/result/{job_id}`.

All 6 requests in that folder run in sequence; the runner uses the saved variables for the result URLs.

### Option B: Postman – Run every endpoint manually

| Order | Folder / Request | What it does |
|-------|------------------|--------------|
| 1 | **1 - Quick flow** → Health | `GET /health` |
| 2 | **1 - Quick flow** → Run All (static data) | `POST /v1/run` with `{}`; sets `session_id`, `job_id_*` |
| 3 | **1 - Quick flow** → Get Result (x4) | `GET /v1/result/{job_id}` for each job |
| 4 | **2 - Session** → Session Keys | `POST /v1/session/keys` (needs real b64 keys) |
| 5 | **2 - Session** → Session Data | `POST /v1/session/data` (needs b64 ciphertexts + count) |
| 6 | **3 - Compute** → (all 4) | `POST /v1/compute/total_payroll`, avg_salary, total_hours, bonus_pool |
| 7 | **4 - Results** → Get Result by job_id | `GET /v1/result/{job_id}` (use any saved job_id) |
| 8 | **5 - Employees** → Create/Update, List, Get, Update, Delete | CRUD with `session_id` and `employee_id` |

For **Session Keys** and **Session Data** you must replace placeholders with real base64 (e.g. from CLI `out/`). For **Employees** you need a valid `session_id` (e.g. from Run All) and real ciphertexts for create/update.

### Option C: cURL – Run all (static) + fetch results

```bash
# 1) Health
curl -s http://localhost:8000/health

# 2) Run all (static data)
RESP=$(curl -s -X POST http://localhost:8000/v1/run -H "Content-Type: application/json" -d '{}')
echo "$RESP"
SESSION_ID=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('session_id',''))")
JOB_TP=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('job_ids',{}).get('total_payroll',''))")
JOB_AS=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('job_ids',{}).get('avg_salary',''))")
JOB_TH=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('job_ids',{}).get('total_hours',''))")
JOB_BP=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('job_ids',{}).get('bonus_pool',''))")

# 3) Wait a moment for jobs to finish, then get results
sleep 2
curl -s "http://localhost:8000/v1/result/$JOB_TP"
curl -s "http://localhost:8000/v1/result/$JOB_AS"
curl -s "http://localhost:8000/v1/result/$JOB_TH"
curl -s "http://localhost:8000/v1/result/$JOB_BP"
```

### Option D: CLI (full flow + decrypt)

```bash
cd server_py
# Server must be running; static data in server_py/static/
python -m client.cli run
# Fetches all job results and decrypts (requires PySEAL + secret key from keygen)
```

---

## Collection variables

| Variable | Set by | Use |
|----------|--------|-----|
| `base_url` | You (default `http://localhost:8000`) | All request URLs |
| `session_id` | Run All (static) Test script | Session, Compute, Employees |
| `job_id_total_payroll`, `job_id_avg_salary`, `job_id_total_hours`, `job_id_bonus_pool` | Run All Test script | Get Result requests |
| `employee_id` | You (default `emp-001`) | Employee CRUD |

---

## Endpoint summary

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness |
| POST | `/v1/run` | One-shot: static or custom keys/data; run all 4 computations |
| POST | `/v1/session/keys` | Create session (HE params + public keys) |
| POST | `/v1/session/data` | Upload batch ciphertexts |
| POST | `/v1/compute/total_payroll` | Sum of salaries |
| POST | `/v1/compute/avg_salary` | Encrypted sum + count (divide locally) |
| POST | `/v1/compute/total_hours` | Sum of hours |
| POST | `/v1/compute/bonus_pool` | Encrypted bonus sum (× rate locally) |
| GET | `/v1/result/{job_id}` | Result ciphertext (decrypt locally) |
| POST | `/v1/session/{session_id}/employees` | Create/update one employee |
| GET | `/v1/session/{session_id}/employees` | List employee_ids |
| GET | `/v1/session/{session_id}/employees/{employee_id}` | Get one employee |
| PUT | `/v1/session/{session_id}/employees/{employee_id}` | Update employee |
| DELETE | `/v1/session/{session_id}/employees/{employee_id}` | Delete employee |

OpenAPI (Swagger): **http://localhost:8000/docs** when the server is running.
