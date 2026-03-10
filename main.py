from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, JSONResponse
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

# ── Config ────────────────────────────────────────────────────────────────────
ML_CLIENT_ID     = os.getenv("ML_CLIENT_ID", "4576804985048120")
ML_CLIENT_SECRET = os.getenv("ML_CLIENT_SECRET", "j0FhuZVrZ3XUhdZIsdddpGISWt39JuHY")
APP_URL          = os.getenv("APP_URL", "https://mltn-sync-production.up.railway.app")
ML_REDIRECT_URI  = f"{APP_URL}/auth/callback"

ML_BASE = "https://api.mercadolibre.com"
TN_BASE = "https://api.tiendanube.com/v1"

# ── In-memory state ───────────────────────────────────────────────────────────
DATA_FILE = "data.json"

def load_data():
    if Path(DATA_FILE).exists():
        with open(DATA_FILE) as f:
            return json.load(f)
    return {
        "ml_accounts": [],
        "tn_account": {},
        "sync_log": [],
        "last_sync": None
    }

def save_data(d):
    with open(DATA_FILE, "w") as f:
        json.dump(d, f, indent=2)

state = load_data()

# ── Models ────────────────────────────────────────────────────────────────────
class TNAccount(BaseModel):
    store_id: str
    token: str

class PublishRequest(BaseModel):
    item_ids: List[str]
    ml_account_index: int

# ── ML OAuth ──────────────────────────────────────────────────────────────────
@app.get("/auth/login")
def ml_login():
    url = (
        f"https://auth.mercadolibre.com.ar/authorization"
        f"?response_type=code"
        f"&client_id={ML_CLIENT_ID}"
        f"&redirect_uri={ML_REDIRECT_URI}"
    )
    return RedirectResponse(url)

@app.get("/auth/callback")
async def ml_callback(code: str = None, error: str = None):
    if error or not code:
        return RedirectResponse(f"{APP_URL}/?error=auth_failed")

    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(
            "https://api.mercadolibre.com/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": ML_CLIENT_ID,
                "client_secret": ML_CLIENT_SECRET,
                "code": code,
                "redirect_uri": ML_REDIRECT_URI,
            },
            headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
        )
        token_data = r.json()

    if "access_token" not in token_data:
        return RedirectResponse(f"{APP_URL}/?error=token_failed")

    access_token = token_data["access_token"]
    refresh_token = token_data.get("refresh_token", "")
    user_id = str(token_data.get("user_id", ""))

    # Get user info
    async with httpx.AsyncClient(timeout=10) as client:
        ur = await client.get(f"{ML_BASE}/users/{user_id}?access_token={access_token}")
        user_info = ur.json()

    nickname = user_info.get("nickname", f"Cuenta {len(state['ml_accounts'])+1}")

    # Check if already exists
    for acc in state["ml_accounts"]:
        if acc["user_id"] == user_id:
            acc["token"] = access_token
            acc["refresh_token"] = refresh_token
            save_data(state)
            return RedirectResponse(f"{APP_URL}/?success=reconnected")

    if len(state["ml_accounts"]) >= 4:
        return RedirectResponse(f"{APP_URL}/?error=max_accounts")

    state["ml_accounts"].append({
        "name": nickname,
        "user_id": user_id,
        "token": access_token,
        "refresh_token": refresh_token
    })
    save_data(state)
    return RedirectResponse(f"{APP_URL}/?success=connected")

@app.post("/auth/refresh/{index}")
async def refresh_token(index: int):
    if index < 0 or index >= len(state["ml_accounts"]):
        raise HTTPException(404)
    acc = state["ml_accounts"][index]
    if not acc.get("refresh_token"):
        raise HTTPException(400, detail="No hay refresh token.")

    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(
            "https://api.mercadolibre.com/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": ML_CLIENT_ID,
                "client_secret": ML_CLIENT_SECRET,
                "refresh_token": acc["refresh_token"],
            },
            headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
        )
        token_data = r.json()

    if "access_token" not in token_data:
        raise HTTPException(400, detail="No se pudo renovar el token.")

    acc["token"] = token_data["access_token"]
    acc["refresh_token"] = token_data.get("refresh_token", acc["refresh_token"])
    save_data(state)
    return {"ok": True}

# ── Helpers TN ────────────────────────────────────────────────────────────────
def tn_headers(token):
    return {
        "Authentication": f"bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "MLTNSync/1.0"
    }

# ── ML helpers ────────────────────────────────────────────────────────────────
async def ml_get_items(user_id: str, token: str):
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(f"{ML_BASE}/users/{user_id}/items/search?limit=50&access_token={token}")
        data = r.json()
        if "error" in data:
            raise HTTPException(400, detail=data.get("message", data["error"]))
        ids = data.get("results", [])
        if not ids:
            return []
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

async def ml_get_description(item_id: str, token: str):
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(f"{ML_BASE}/items/{item_id}/description?access_token={token}")
        return r.json().get("plain_text", "")

# ── API routes ────────────────────────────────────────────────────────────────
@app.get("/api/state")
def get_state():
    return {
        "ml_accounts": [{"name": a["name"], "user_id": a["user_id"]} for a in state["ml_accounts"]],
        "tn_connected": bool(state["tn_account"].get("store_id")),
        "tn_store_id": state["tn_account"].get("store_id", ""),
        "last_sync": state["last_sync"],
        "sync_log": state["sync_log"][-50:]
    }

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
    if req.ml_account_index < 0 or req.ml_account_index >= len(state["ml_accounts"]):
        raise HTTPException(404, detail="Cuenta ML no encontrada.")

    acc = state["ml_accounts"][req.ml_account_index]
    tn = state["tn_account"]
    results = []

    for item_id in req.item_ids:
        try:
            product = await ml_get_item(item_id, acc["token"])
            if "error" in product:
                results.append({"id": item_id, "ok": False, "msg": product.get("message", "Error ML")})
                continue
            description = await ml_get_description(item_id, acc["token"])
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
                    f"{TN_BASE}/{tn['store_id']}/products",
                    headers=tn_headers(tn["token"]),
                    json=payload
                )
                resp = r.json()
                ok = r.status_code in (200, 201)
                msg = "Publicado" if ok else (resp.get("description") or resp.get("message") or f"Error {r.status_code}")
                results.append({"id": item_id, "title": product.get("title",""), "ok": ok, "msg": msg})
                state["sync_log"].append({"ts": int(time.time()), "action": "publish", "product": product.get("title",""), "status": "ok" if ok else "error"})
                save_data(state)
            await asyncio.sleep(0.3)
        except Exception as e:
            results.append({"id": item_id, "ok": False, "msg": str(e)})

    return {"results": results}

@app.post("/api/sync/{index}")
async def sync_account(index: int):
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
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.get(f"{TN_BASE}/{tn['store_id']}/products?q={p['id']}", headers=tn_headers(tn["token"]))
                tn_products = r.json()
                tn_product = None
                tn_variant = None
                if isinstance(tn_products, list):
                    for tp in tn_products:
                        for v in tp.get("variants", []):
                            if v.get("sku") == p["id"]:
                                tn_product = tp
                                tn_variant = v
                                break

                if tn_product and tn_variant:
                    r2 = await client.put(
                        f"{TN_BASE}/{tn['store_id']}/products/{tn_product['id']}/variants/{tn_variant['id']}",
                        headers=tn_headers(tn["token"]),
                        json={"price": str(p.get("price", 0)), "stock": p.get("available_quantity", 0)}
                    )
                    ok = r2.status_code in (200, 201)
                    results.append({"title": p["title"], "ok": ok, "action": "updated"})
                    state["sync_log"].append({"ts": int(time.time()), "action": "sync", "product": p["title"], "status": "ok" if ok else "error"})
                else:
                    results.append({"title": p["title"], "ok": False, "action": "no_encontrado_en_TN"})
            await asyncio.sleep(0.2)
        except Exception as e:
            results.append({"title": p["title"], "ok": False, "action": str(e)})

    state["last_sync"] = int(time.time())
    save_data(state)
    return {"results": results, "total": len(results)}

# ── Serve frontend ─────────────────────────────────────────────────────────────
frontend_path = Path("frontend")
if frontend_path.exists():
    app.mount("/", StaticFiles(directory=str(frontend_path), html=True), name="frontend")
