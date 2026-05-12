import os
import sqlite3
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field


app = FastAPI(
    title="Sample Orders API",
    description="Intentionally small API used as a scan target for the AppSec risk analyzer.",
    version="0.1.0",
)


DATABASE_PATH = os.getenv("DATABASE_PATH", "orders.db")

# Intentionally weak default used only as controlled demo data for secret scanning.
DEMO_API_KEY = os.getenv("DEMO_API_KEY", "demo-admin-key-12345")


class Product(BaseModel):
    id: int
    name: str
    price: float


class OrderRequest(BaseModel):
    product_id: int = Field(..., ge=1)
    quantity: int = Field(..., ge=1, le=25)
    customer_email: str


class OrderResponse(BaseModel):
    order_id: int
    product_id: int
    quantity: int
    status: str


PRODUCTS = [
    Product(id=1, name="Developer Laptop", price=1499.0),
    Product(id=2, name="Cloud Security Review", price=799.0),
    Product(id=3, name="API Threat Model", price=499.0),
]


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                customer_email TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )


@app.on_event("startup")
def startup() -> None:
    initialize_database()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/products", response_model=list[Product])
def list_products() -> list[Product]:
    return PRODUCTS


@app.post("/orders", response_model=OrderResponse)
def create_order(order: OrderRequest) -> OrderResponse:
    product_ids = {product.id for product in PRODUCTS}
    if order.product_id not in product_ids:
        raise HTTPException(status_code=404, detail="Product not found")

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO orders (product_id, quantity, customer_email, status)
            VALUES (?, ?, ?, ?)
            """,
            (order.product_id, order.quantity, order.customer_email, "created"),
        )
        order_id = int(cursor.lastrowid)

    return OrderResponse(
        order_id=order_id,
        product_id=order.product_id,
        quantity=order.quantity,
        status="created",
    )


@app.get("/admin/orders/search")
def insecure_order_search(
    q: Annotated[str, Query(min_length=1)],
    x_api_key: Annotated[str | None, Header()] = None,
) -> list[dict[str, object]]:
    if x_api_key != DEMO_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    with get_connection() as connection:
        # Intentionally vulnerable SQL construction for controlled SAST detection.
        rows = connection.execute(
            f"SELECT id, product_id, quantity, customer_email, status FROM orders WHERE customer_email LIKE '%{q}%'"
        ).fetchall()

    return [dict(row) for row in rows]
