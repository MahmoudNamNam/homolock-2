# Deploy HomoLock-HR on AWS

This guide covers deploying the API on AWS and **how to use it** from clients (Postman, CLI, cURL).

---

## Deploy options

| Option | Best for | Notes |
|--------|----------|--------|
| **EC2** | Full control, PySEAL on the box | See [EC2 steps](#ec2-steps) below. Main docs: repo root [README.md](../../README.md) “Deploy on a single server”. |
| **ECS / Fargate** | Containerized, auto-scaling | Use the [Dockerfile](../Dockerfile) (if present) or build from `server_py/`; run uvicorn in the container. |
| **Elastic Beanstalk** | Managed app platform | Upload app (or Docker); set env `HOMOLOCK_DATA_DIR` and port. |

Recommended for simplicity: **EC2** + systemd (see README).

---

## EC2 steps (summary)

1. **Launch**: Ubuntu 22.04, e.g. `t3.small`. Security group: **SSH (22)** and **TCP 8000** (or your app port) from allowed IPs.
2. **Install & run**: Follow the full [README “Deploy on a single server”](../../README.md) (clone, venv, `pip install -r requirements.txt`, PySEAL, `HOMOLOCK_DATA_DIR`, systemd).
3. **Static data (for zero-config run)**: On the server:
   ```bash
   cd ~/Homolock/server_py
   source .venv/bin/activate
   python -m scripts.generate_static_data
   ```
   This fills `server_py/static/` so `POST /v1/run` with body `{}` works without client uploads.
4. **HTTPS (optional)**: Put Nginx or Caddy in front of uvicorn, use a domain and certificate (e.g. ACM). Then clients use `https://your-domain.com` as base URL.

---

## How to use the API when deployed on AWS

Once the server is running (e.g. at `http://<EC2_PUBLIC_IP>:8000` or `https://your-domain.com`), use that URL as the **base URL** everywhere.

### 1. Postman

- Import the collection: `server_py/postman/HomoLock-HR.postman_collection.json`.
- Set the collection variable **`base_url`** to your deployed URL, e.g.:
  - `http://<EC2_PUBLIC_IP>:8000`
  - or `https://your-domain.com` if you use a reverse proxy with TLS.
- Run folder **“1 - Quick flow (static)”** as usual (Health → Run All → Get results). No other change needed.

### 2. CLI (Python client)

Pass the deployed URL with `--server`:

```bash
cd Homolock
export PYTHONPATH="$(pwd)/server_py:$PYTHONPATH"

# One-shot run (uses server static data), then fetch and decrypt results
python3 -m client.cli run --server http://<EC2_PUBLIC_IP>:8000

# Or with HTTPS
python3 -m client.cli run --server https://your-domain.com
```

Other commands (upload session, compute, employees) also take `--server`:

```bash
python3 -m client.cli upload-session --server http://<EC2_PUBLIC_IP>:8000 --session-id my-session
python3 -m client.cli compute --session-id my-session --server http://<EC2_PUBLIC_IP>:8000
```

### 3. cURL

Replace `BASE` with your deployed base URL:

```bash
BASE="http://<EC2_PUBLIC_IP>:8000"

curl -s "$BASE/health"
curl -s -X POST "$BASE/v1/run" -H "Content-Type: application/json" -d '{}'
# Then GET /v1/result/{job_id} for each job_id from the run response
```

### 4. One-shot “run all” (static data) from anywhere

If the server has static data generated (`python -m scripts.generate_static_data` on the server):

1. **POST** `https://your-deployed-url/v1/run` with body `{}`.
2. Response: `session_id` and `job_ids` (e.g. `total_payroll`, `avg_salary`, `total_hours`, `bonus_pool`).
3. **GET** `https://your-deployed-url/v1/result/{job_id}` for each `job_id` (decrypt the returned ciphertext locally).

No keys or ciphertexts need to be sent when using static data.

---

## Environment variables (server)

| Variable | Default | Description |
|----------|---------|-------------|
| `HOMOLOCK_DATA_DIR` | `data` | Directory for sessions, jobs, and file DB (use a persistent path on EC2/ECS, e.g. `/var/lib/homolock` or EFS). |

Port and host are set by how you start uvicorn (e.g. `--host 0.0.0.0 --port 8000`).

---

## Security notes

- **No auth in the app**: The API does not implement authentication. Restrict access with a security group (only your IPs or VPN), and/or put the app behind an API gateway or reverse proxy that adds auth.
- **HTTPS**: Use TLS in front of the app (e.g. ALB + ACM, or Nginx/Caddy with a certificate) so clients use `https://`.
- **Secret key**: Never deploy or send `secret_key.seal` to the server; decryption stays on the client.

---

## Optional: Docker (for ECS or local)

If you add a `Dockerfile` in `server_py/` (see below), you can run the app in a container and deploy to ECS/Fargate. Set `HOMOLOCK_DATA_DIR` in the task definition and use a persistent volume (e.g. EFS) if you need session/job data to survive restarts.

Example minimal Dockerfile (no PySEAL; compute endpoints will return 503 until you use an image with SEAL):

```dockerfile
FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY static ./static
ENV HOMOLOCK_DATA_DIR=/data
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

For full HE support, build an image that installs PySEAL (e.g. from a prebuilt wheel or SEAL-Python) before copying the app.
