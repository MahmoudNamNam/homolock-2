# Employee data (CSV or JSON)

Use either format for CRUD / upload flows. Same shape:

- **CSV:** `employee_id,salary_cents,hours,bonus_points` (header row, then one row per employee).
- **JSON:** Array of objects: `{"employee_id": "1001", "salary_cents": 850000, "hours": 160, "bonus_points": 10}`.

CLI: `encrypt-hr --csv data/employees.csv` or `encrypt-hr --json data/employees.json`.  
Upload script: `python -m scripts.upload_from_csv --csv ../data/employees.csv` or `--json ../data/employees.json`.
