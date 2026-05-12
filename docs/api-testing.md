# API Testing Notes

This document explains how to manually test the sample API during local development.

The API is intentionally small. Its purpose is not to model a full business system, but to provide a realistic target for security scanning and risk analysis.

## Start the API

From the repository root:

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload
```

Open the interactive API documentation:

```text
http://127.0.0.1:8000/docs
```

## Endpoint Overview

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Confirms that the API is running. |
| GET | `/products` | Returns the sample product catalog. |
| POST | `/orders` | Creates a sample order in SQLite. |
| GET | `/admin/orders/search` | Searches orders by customer email. This endpoint contains an intentional SQL weakness for SAST testing. |

## 1. Health Check

Use this endpoint first to confirm the service is alive.

Request:

```http
GET /health
```

Expected response:

```json
{
  "status": "ok"
}
```

## 2. List Products

This endpoint returns static product data.

Request:

```http
GET /products
```

Expected response:

```json
[
  {
    "id": 1,
    "name": "Developer Laptop",
    "price": 1499.0
  },
  {
    "id": 2,
    "name": "Cloud Security Review",
    "price": 799.0
  },
  {
    "id": 3,
    "name": "API Threat Model",
    "price": 499.0
  }
]
```

## 3. Create an Order

This endpoint writes an order to the local SQLite database.

Request:

```http
POST /orders
Content-Type: application/json
```

Body:

```json
{
  "product_id": 2,
  "quantity": 1,
  "customer_email": "alice@example.com"
}
```

Expected response:

```json
{
  "order_id": 1,
  "product_id": 2,
  "quantity": 1,
  "status": "created"
}
```

## 4. Search Orders as Admin

This endpoint requires the demo API key.

Request:

```http
GET /admin/orders/search?q=alice
X-API-Key: demo-admin-key-12345
```

Expected response:

```json
[
  {
    "id": 1,
    "product_id": 2,
    "quantity": 1,
    "customer_email": "alice@example.com",
    "status": "created"
  }
]
```

## Intentional Security Notes

The admin search endpoint currently builds part of a SQL query using string formatting. This is intentional and should be detected later by SAST tooling.

The API also has a weak fallback API key. This is intentional test data for secret scanning and risk scoring.

These examples are controlled weaknesses. They should remain documented so a reviewer understands that the insecure patterns are included for the DevSecOps pipeline, not by accident.

## Cleanup

The API creates a local SQLite database file named:

```text
orders.db
```

This file is ignored by Git and can be deleted when local test data is no longer needed.

