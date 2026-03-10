from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
import httpx
import asyncio
import json
import os
import time
from pathlib import Path

app = FastAPI(title="ML-TN Sync")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory state (persisted to file) ───────────────────────────────────────
DATA_FILE = "data.json"

def load_data():
    if Path(DATA_FILE).exists():
        with open(DATA_FILE) as f:
            return json.load(f)
    return {
        "ml_accounts": [],   # [{name, token, user_id}]
        "tn_account": {},    # {store_id, token}
        "sync_log": [],      # [{ts, action, product, status}]
        "last_sync": None
    }

def save_data(d):
    with open(DATA_FILE, "w") as f:
        json.dump(d, f, indent=2)

state = load_data()

# ── Models ────────────────────────────────────────────────────────────────────
class MLAccount(BaseModel):
    name: str
    token: str
    user_id: str

class TNAccount(BaseModel):
    store_id: str
    token: str

class PublishRequest(BaseModel):
    item_ids: List[str]   # ML item IDs
    ml_token: str         # which ML account token to use

class SyncRequest(BaseModel):
    ml_account_index: int

# ── ML helpers ────────────────────────────────────────────────────────────────
ML_BASE = "https://api.mercadolibre.com"
TN_BASE = "https://api.tiendanube.com/v1"
HEADERS_TN = lambda token: {
    "Authentication": f"bearer {token}",
    "Content-Type": "application/json",
    "User-Agent": "MLTNSync/1.0"
}

async def ml_get_items(user_id: str, token: str):
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(f"{ML_BASE}/users/{user_id}/items/search?limit=50&access_token={token}")
        data = r.json()
        if "error" in data:
            raise HTTPException(400, detail=data.get("message", data["error"]))
        ids = data.get("results", [])
        if not ids:
            return []
        # batch fetch details
        products = []
        for i in range(0, len(ids), 20):
            batch = ids[i:i+20]
            r2 = await client.get(f"{ML_BASE}/items?ids={','.join(batch)}&access_token={token}")
            for item in r2.json():
                if item.get("code") == 200:
                    products.append(item["body"])
        return products

async def ml_get_item(item_id: str, token: str):
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(f"{ML_BASE}/items/{item_id}?access_token={token}")
        return r.json()

async def ml_get_description(item_id: str):
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(f"{ML_BASE}/items/{item_id}/description")
        return r.json().get("plain_text", "")

async def tn_create_product(product: dict, store_id: str, token: str):
    description = await ml_get_description(product["id"])
    payload = {
        "name": {"es": product["title"]},
        "description": {"es": description or product["title"]},
        "published": True,
        "variants": [{
            "price": str(product.get("price", 0)),
            "stock_management": True,
            "stock": product.get("available_quantity", 0),
            "sku": product["id"],
        }],
        "images": [{"src": p["url"]} for p in (product.get("pictures") or [])[:5]]
    }
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{TN_BASE}/{store_id}/products",
            headers=HEADERS_TN(token),
            json=payload
        )
        return r.status_code, r.json()

async def tn_find_product_by_sku(sku: str, store_id: str, token: str):
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(
            f"{TN_BASE}/{store_id}/products?q={sku}",
            headers=HEADERS_TN(token)
        )
        products = r.json()
        if isinstance(products, list):
            for p in products:
                for v in p.get("variants", []):
                    if v.get("sku") == sku:
                        return p, v
    return None, None

async def tn_update_variant(product_id: int, variant_id: int, price: float, stock: int, store_id: str, token: str):
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.put(
            f"{TN_BASE}/{store_id}/products/{product_id}/variants/{variant_id}",
            headers=HEADERS_TN(token),
            json={"price": str(price), "stock": stock}
        )
        return r.status_code, r.json()

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/api/state")
def get_state():
    return {
        "ml_accounts": [{"name": a["name"], "user_id": a["user_id"]} for a in state["ml_accounts"]],
        "tn_connected": bool(state["tn_account"].get("store_id")),
        "tn_store_id": state["tn_account"].get("store_id", ""),
        "last_sync": state["last_sync"],
        "sync_log": state["sync_log"][-50:]
    }

@app.post("/api/ml/add")
def add_ml_account(acc: MLAccount):
    # Validate token
    for existing in state["ml_accounts"]:
        if existing["user_id"] == acc.user_id:
            raise HTTPException(400, detail="Esta cuenta ya está agregada.")
    if len(state["ml_accounts"]) >= 4:
        raise HTTPException(400, detail="Máximo 4 cuentas de ML.")
    state["ml_accounts"].append(acc.dict())
    save_data(state)
    return {"ok": True, "total": len(state["ml_accounts"])}

@app.delete("/api/ml/{index}")
def remove_ml_account(index: int):
    if index < 0 or index >= len(state["ml_accounts"]):
        raise HTTPException(404)
    removed = state["ml_accounts"].pop(index)
    save_data(state)
    return {"ok": True, "removed": removed["name"]}

@app.post("/api/tn/connect")
def connect_tn(acc: TNAccount):
    state["tn_account"] = acc.dict()
    save_data(state)
    return {"ok": True}

@app.get("/api/ml/{index}/products")
async def get_ml_products(index: int):
    if index < 0 or index >= len(state["ml_accounts"]):
        raise HTTPException(404, detail="Cuenta no encontrada.")
    acc = state["ml_accounts"][index]
    products = await ml_get_items(acc["user_id"], acc["token"])
    return {"products": products, "total": len(products)}

@app.post("/api/publish")
async def publish_products(req: PublishRequest):
    if not state["tn_account"].get("store_id"):
        raise HTTPException(400, detail="Tienda Nube no conectada.")

    tn = state["tn_account"]
    results = []

    for item_id in req.item_ids:
        try:
            product = await ml_get_item(item_id, req.ml_token)
            if "error" in product:
                results.append({"id": item_id, "ok": False, "msg": product.get("message", "Error ML")})
                continue
            status, resp = await tn_create_product(product, tn["store_id"], tn["token"])
            ok = status in (200, 201)
            msg = "Publicado" if ok else (resp.get("description") or resp.get("message") or f"Error {status}")
            results.append({"id": item_id, "title": product.get("title",""), "ok": ok, "msg": msg})
            log_entry = {"ts": int(time.time()), "action": "publish", "product": product.get("title",""), "status": "ok" if ok else "error"}
            state["sync_log"].append(log_entry)
            save_data(state)
            await asyncio.sleep(0.3)
        except Exception as e:
            results.append({"id": item_id, "ok": False, "msg": str(e)})

    return {"results": results}

@app.post("/api/sync/{index}")
async def sync_account(index: int):
    """Sync prices and stock from ML account to TN"""
    if index < 0 or index >= len(state["ml_accounts"]):
        raise HTTPException(404)
    if not state["tn_account"].get("store_id"):
        raise HTTPException(400, detail="Tienda Nube no conectada.")

    acc = state["ml_accounts"][index]
    tn = state["tn_account"]
    products = await ml_get_items(acc["user_id"], acc["token"])
    results = []

    for p in products:
        try:
            tn_product, tn_variant = await tn_find_product_by_sku(p["id"], tn["store_id"], tn["token"])
            if tn_product and tn_variant:
                status, _ = await tn_update_variant(
                    tn_product["id"], tn_variant["id"],
                    p.get("price", 0), p.get("available_quantity", 0),
                    tn["store_id"], tn["token"]
                )
                ok = status in (200, 201)
                results.append({"title": p["title"], "ok": ok, "action": "updated"})
                log_entry = {"ts": int(time.time()), "action": "sync", "product": p["title"], "status": "ok" if ok else "error"}
                state["sync_log"].append(log_entry)
            else:
                results.append({"title": p["title"], "ok": False, "action": "not_found_in_tn"})
            await asyncio.sleep(0.2)
        except Exception as e:
            results.append({"title": p["title"], "ok": False, "action": str(e)})

    state["last_sync"] = int(time.time())
    save_data(state)
    return {"results": results, "total": len(results)}

# Serve frontend
frontend_path = Path("frontend")
if frontend_path.exists():
    app.mount("/", StaticFiles(directory=str(frontend_path), html=True), name="frontend")
