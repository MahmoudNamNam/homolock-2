# Seeing actual data and operations

## How to see actual (decrypted) data

The server **never** sees plaintext; only the client with the **secret key** can decrypt.

### Aggregate results (totals, averages, bonus pool)

After you run **compute** (total_payroll, avg_salary, total_hours, bonus_pool):

1. **CLI:**  
   `python -m client.cli fetch-decrypt --job-id <job_id>`  
   Prints the decrypted number (e.g. total payroll sum, or avg = sum/count, or bonus pool).

2. **API + your code:**  
   `GET /v1/result/{job_id}` → use `result_ciphertext_b64` and decrypt with your secret key (same as CLI: load context + secret key, decrypt ciphertext, decode batch slot 0).

3. **One-shot:**  
   `python -m client.cli run` does upload → compute → fetch-decrypt for all four and prints the actual totals.

### Per-employee actual data (one row)

- **Your CSV/JSON** (`data/employees.csv` or `data/employees.json`) is the plaintext source. You can open it to see salary, hours, bonus_points for each employee.

- **From the API (encrypted → decrypt on client):**  
  Fetch one employee’s ciphertexts, then decrypt with the secret key:
  - **CLI:**  
    `python -m client.cli employee get --session-id <id> --employee-id 1001 --decrypt`  
    Prints `salary_cents`, `hours`, `bonus_points` (actual numbers). Requires `out/secret_key.seal` from the same keys used to create the session.

  - **API:**  
    `GET /v1/session/{session_id}/employees/{employee_id}` returns `salary_ct_b64`, `hours_ct_b64`, `bonus_points_ct_b64`. Decrypt each with your secret key (BatchDecoder slot 0) to get the three numbers.

---

## What operations can be done

### On the server (on ciphertext)

Only **sum** and **count** (no key, no plaintext):

| Operation      | Endpoint / job   | Meaning |
|----------------|------------------|--------|
| Sum of salaries | total_payroll   | Total payroll (sum of salary_cents). |
| Sum + count     | avg_salary       | Encrypted sum + count; you decrypt and compute **avg = sum / count** locally. |
| Sum of hours    | total_hours      | Total hours. |
| Sum for bonus   | bonus_pool       | Encrypted sum of salaries; you decrypt and compute **sum × bonus_rate_bps / 10000** locally. |

No filtering, sorting, or per-row operations on the server.

### On the client (on plaintext or after decrypting)

You can do **any** operations on:

- Your **CSV/JSON** (filter, sort, sum, avg, min, max, etc.).
- **Decrypted aggregates** (e.g. use the sum and count from avg_salary to compute average, or apply bonus rate to bonus_pool sum).
- **Per-employee decrypted values** (after `employee get --decrypt` or decrypting the three ciphertexts yourself): any math or logic you want.

---

## Add employee with plain values (no base64)

- **API:** `POST /v1/session/{session_id}/employees/plain`  
  Body: `{ "employee_id": "1001", "salary_cents": 850000, "hours": 160, "bonus_points": 10 }`.  
  Server encrypts and stores; you never send base64.

## Increase or decrease values without seeing actual data

You can **add deltas** (plain integers) to an employee’s salary, hours, or bonus_points. The server encrypts the deltas and adds homomorphically; it never sees the stored values.

- **API:** `PATCH /v1/session/{session_id}/employees/{employee_id}/adjust`  
  Body: **plain ints** — `salary_delta`, `hours_delta`, `bonus_points_delta` (optional; send only what you want to change). Example: `{ "salary_delta": 50000, "hours_delta": 0, "bonus_points_delta": 2 }`. No base64.
- **CLI:**  
  `python -m client.cli employee adjust --session-id X --employee-id 1001 --salary-delta 50000 --hours-delta 0 --bonus-delta 2`

---

## Summary

| Goal | How |
|------|-----|
| See **aggregate** actual numbers (totals, avg, bonus pool) | Run compute → `fetch-decrypt --job-id <id>` or GET result and decrypt. |
| See **one employee** actual salary/hours/bonus_points | Use your CSV/JSON, or `employee get --decrypt` (CLI) or GET employee + decrypt in your code. |
| **Increase/decrease** salary, hours, bonus without revealing values | `PATCH .../employees/{id}/adjust` with encrypted deltas, or CLI `employee adjust --salary-delta N`. |
| Do **sum/count** on salary, hours, or bonus | Use server compute (total_payroll, avg_salary, total_hours, bonus_pool). |
| Do **other ops** (filter, sort, formulas) | Use plaintext (CSV/JSON) or decrypted results on the client. |
