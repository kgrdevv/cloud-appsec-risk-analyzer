# Sample Orders API

This is a deliberately small FastAPI application used as the scan target for Cloud AppSec Risk Analyzer.

## What This API Does

The API models a simple order service:

- `GET /health` returns service health.
- `GET /products` returns a static product catalog.
- `POST /orders` creates an order in SQLite.
- `GET /admin/orders/search` searches orders by customer email.

## Why It Exists

In a real DevSecOps workflow, scanners need something concrete to inspect. This API gives the project a realistic target for:

- SAST scanning with Semgrep.
- Dependency scanning with Trivy.
- Secret scanning with Gitleaks.
- Container scanning after the API is packaged with Docker.

## Intentional Weaknesses

This application contains controlled weaknesses for learning and testing:

- A weak demo API key fallback.
- An intentionally unsafe SQL query in the admin search endpoint.
- Simple authentication logic that is not production-grade.

These examples are intentionally included so the security pipeline can detect, normalize, and prioritize findings later in the project.

## Local Run

After Python is installed, run:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The API will be available at:

```text
http://127.0.0.1:8000
```

FastAPI also provides interactive documentation at:

```text
http://127.0.0.1:8000/docs
```

