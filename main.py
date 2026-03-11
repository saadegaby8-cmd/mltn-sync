from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict
import httpx
import asyncio
import json
import os
import time
import hashlib
import secrets
from pathlib import Path

app = FastAPI(title="ML-TN Sync")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

ML_CLIENT_ID     = os.getenv("ML_CLIENT_ID", "4576804985048120")
ML_CLIENT_SECRET = os.getenv("ML_CLIENT_SECRET", "j0FhuZVrZ3XUhdZIsdddpGISWt39JuHY")
APP_URL          = os.getenv("APP_URL", "https://mltn-sync-production.up.railway.app")
ML_REDIRECT_URI  = f"{APP_URL}/auth/callback"
ADMIN_EMAIL      = os.getenv("ADMIN_EMAIL", "admin@sync.com")
ADMIN_PASSWORD   = os.getenv("ADMIN_PASSWORD", "sync1234")

ML_BASE = "https://api.mercadolibre.com"
TN_BASE = "https://api.tiendanube.com/v1"
DATA_FILE = "data.json"
SESSIONS: Dict[str, float] = {}

def load_data():
    if Path(DATA_FILE).exists():
        with open(DATA_FILE) as f:
            return json.load(f)
    return {"ml_accounts": [], "tn_account": {}, "sync_log": [], "last_sync": None, "links": []}

def save_data(d):
    with open(DATA_FILE, "w") as f:
        json.dump(d, f, indent=2)

state = load_data()
if "links" not in state:
    state["links"] = []

def tn_headers(token):
    return {"Authentication": f"bearer {token}", "Content-Type": "application/json", "User-Agent": "MLTNSync/1.0"}

# ── Auth ──────────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: str
    password: str

def get_session(request: Request):
    token = request.headers.get("X-Session-Token")
    if not token or token not in SESSIONS or SESSIONS[token] < time.time():
        raise HTTPException(401, detail="No autorizado.")
    SESSIONS[token] = time.time() + 86400 * 7
    return token

@app.post("/api/login")
def login(req: LoginRequest):
    if req.email.strip().lower() != ADMIN_EMAIL.lower() or req.password != ADMIN_PASSWORD:
        raise HTTPException(401, detail="Email o contraseña incorrectos.")
    token = secrets.token_hex(32)
    SESSIONS[token] = time.time() + 86400 * 7
    return {"token": token, "ok": True}

@app.post("/api/logout")
def logout(session: str = Depends(get_session)):
    SESSIONS.pop(session, None)
    return {"ok": True}

# ── ML OAuth ──────────────────────────────────────────────────────────────────
@app.get("/auth/login")
def ml_login():
    url = f"https://auth.mercadolibre.com.ar/authorization?response_type=code&client_id={ML_CLIENT_ID}&redirect_uri={ML_REDIRECT_URI}"
    return RedirectResponse(url)

@app.get("/auth/callback")
async def ml_callback(code: str = None, error: str = None):
    if error or not code:
        return RedirectResponse(f"{APP_URL}/?error=auth_failed")
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(
            "https://api.mercadolibre.com/oauth/token",
            data={"grant_type": "authorization_code", "client_id": ML_CLIENT_ID,
                  "client_secret": ML_CLIENT_SECRET, "code": code, "redirect_uri": ML_REDIRECT_URI},
            headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
        )
        td = r.json()
    if "access_token" not in td:
        return RedirectResponse(f"{APP_URL}/?error=token_failed")
    access_token = td["access_token"]
    refresh_token = td.get("refresh_token", "")
    user_id = str(td.get("user_id", ""))
    expires_in = td.get("expires_in", 21600)
    async with httpx.AsyncClient(timeout=10) as client:
        ur = await client.get(f"{ML_BASE}/users/{user_id}?access_token={access_token}")
        user_info = ur.json()
    nickname = user_info.get("nickname", f"Cuenta {len(state['ml_accounts'])+1}")
    for acc in state["ml_accounts"]:
        if acc["user_id"] == user_id:
            acc["token"] = access_token
            acc["refresh_token"] = refresh_token
            acc["token_expiry"] = time.time() + expires_in - 300
            save_data(state)
            return RedirectResponse(f"{APP_URL}/?success=reconnected")
    if len(state["ml_accounts"]) >= 4:
        return RedirectResponse(f"{APP_URL}/?error=max_accounts")
    state["ml_accounts"].append({
        "name": nickname, "user_id": user_id, "token": access_token,
        "refresh_token": refresh_token, "token_expiry": time.time() + expires_in - 300
    })
    save_data(state)
    return RedirectResponse(f"{APP_URL}/?success=connected")

async def get_valid_token(index: int) -> str:
    acc = state["ml_accounts"][index]
    if time.time() > acc.get("token_expiry", 0) and acc.get("refresh_token"):
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.post(
                    "https://api.mercadolibre.com/oauth/token",
                    data={"grant_type": "refresh_token", "client_id": ML_CLIENT_ID,
                          "client_secret": ML_CLIENT_SECRET, "refresh_token": acc["refresh_token"]},
                    headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
                )
                td = r.json()
            if "access_token" in td:
                acc["token"] = td["access_token"]
                acc["refresh_token"] = td.get("refresh_token", acc["refresh_token"])
                acc["token_expiry"] = time.time() + td.get("expires_in", 21600) - 300
                save_data(state)
        except:
            pass
    return acc["token"]

# ── ML helpers ────────────────────────────────────────────────────────────────
async def ml_get_all_items(user_id: str, token: str) -> list:
    all_ids = []
    offset = 0
    limit = 100
    async with httpx.AsyncClient(timeout=30) as client:
        while True:
            r = await client.get(f"{ML_BASE}/users/{user_id}/items/search?limit={limit}&offset={offset}&access_token={token}")
            data = r.json()
            if "error" in data:
                raise HTTPException(400, detail=data.get("message", data["error"]))
            ids = data.get("results", [])
            all_ids.extend(ids)
            total = data.get("paging", {}).get("total", 0)
            offset += limit
            if offset >= total or not ids:
                break
            await asyncio.sleep(0.1)
    if not all_ids:
        return []
    products = []
    async with httpx.AsyncClient(timeout=60) as client:
        for i in range(0, len(all_ids), 20):
            batch = all_ids[i:i+20]
            r = await client.get(f"{ML_BASE}/items?ids={','.join(batch)}&access_token={token}")
            for item in r.json():
                if item.get("code") == 200:
                    body = item["body"]
                    variations = body.get("variations", [])
                    body["_has_variations"] = len(variations) > 0
                    body["_variation_count"] = len(variations)
                    # Clean up variation attributes for display
                    for v in variations:
                        v["_attrs"] = {a["name"]: a["value_name"] for a in v.get("attribute_combinations", [])}
                    products.append(body)
            await asyncio.sleep(0.05)
    return products

# ── Models ────────────────────────────────────────────────────────────────────
class TNAccount(BaseModel):
    store_id: str
    token: str

class PublishRequest(BaseModel):
    item_ids: List[str]
    ml_account_index: int

class LinkRequest(BaseModel):
    ml_item_id: str
    ml_variation_id: Optional[str] = None
    ml_account_index: int
    tn_product_id: str
    tn_variant_id: Optional[str] = None

class UnlinkRequest(BaseModel):
    ml_item_id: str
    ml_variation_id: Optional[str] = None

class DuplicateRequest(BaseModel):
    item_ids: List[str]
    from_account: int
    to_account: int

# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/api/state")
def get_state(_: str = Depends(get_session)):
    return {
        "ml_accounts": [{"name": a["name"], "user_id": a["user_id"],
                         "token_ok": time.time() < a.get("token_expiry", 0)} for a in state["ml_accounts"]],
        "tn_connected": bool(state["tn_account"].get("store_id")),
        "tn_store_id": state["tn_account"].get("store_id", ""),
        "last_sync": state["last_sync"],
        "sync_log": state["sync_log"][-100:],
        "links": state.get("links", [])
    }

@app.delete("/api/ml/{index}")
def remove_ml_account(index: int, _: str = Depends(get_session)):
    if index < 0 or index >= len(state["ml_accounts"]):
        raise HTTPException(404)
    removed = state["ml_accounts"].pop(index)
    save_data(state)
    return {"ok": True, "removed": removed["name"]}

@app.post("/api/tn/connect")
def connect_tn(acc: TNAccount, _: str = Depends(get_session)):
    state["tn_account"] = acc.dict()
    save_data(state)
    return {"ok": True}

@app.get("/api/ml/{index}/products")
async def get_ml_products(index: int, _: str = Depends(get_session)):
    if index < 0 or index >= len(state["ml_accounts"]):
        raise HTTPException(404)
    acc = state["ml_accounts"][index]
    token = await get_valid_token(index)
    products = await ml_get_all_items(acc["user_id"], token)
    return {"products": products, "total": len(products)}

@app.get("/api/tn/products")
async def get_tn_products(_: str = Depends(get_session)):
    if not state["tn_account"].get("store_id"):
        raise HTTPException(400, detail="Tienda Nube no conectada.")
    tn = state["tn_account"]
    all_products = []
    page = 1
    async with httpx.AsyncClient(timeout=30) as client:
        while True:
            r = await client.get(f"{TN_BASE}/{tn['store_id']}/products?page={page}&per_page=50",
                                 headers=tn_headers(tn["token"]))
            data = r.json()
            if not isinstance(data, list) or not data:
                break
            all_products.extend(data)
            if len(data) < 50:
                break
            page += 1
            await asyncio.sleep(0.1)
    return {"products": all_products, "total": len(all_products)}

@app.post("/api/links/add")
def add_link(req: LinkRequest, _: str = Depends(get_session)):
    links = state.get("links", [])
    link_key = req.ml_item_id + ("_" + req.ml_variation_id if req.ml_variation_id else "")
    links = [l for l in links if (l["ml_item_id"] + ("_" + l.get("ml_variation_id","") if l.get("ml_variation_id") else "")) != link_key]
    links.append({
        "ml_item_id": req.ml_item_id,
        "ml_variation_id": req.ml_variation_id,
        "ml_account_index": req.ml_account_index,
        "tn_product_id": req.tn_product_id,
        "tn_variant_id": req.tn_variant_id
    })
    state["links"] = links
    save_data(state)
    return {"ok": True}

@app.post("/api/links/remove")
def remove_link(req: UnlinkRequest, _: str = Depends(get_session)):
    link_key = req.ml_item_id + ("_" + req.ml_variation_id if req.ml_variation_id else "")
    state["links"] = [l for l in state.get("links", [])
                      if (l["ml_item_id"] + ("_" + l.get("ml_variation_id","") if l.get("ml_variation_id") else "")) != link_key]
    save_data(state)
    return {"ok": True}

@app.post("/api/publish")
async def publish_products(req: PublishRequest, _: str = Depends(get_session)):
    if not state["tn_account"].get("store_id"):
        raise HTTPException(400, detail="Tienda Nube no conectada.")
    if req.ml_account_index < 0 or req.ml_account_index >= len(state["ml_accounts"]):
        raise HTTPException(404)
    acc = state["ml_accounts"][req.ml_account_index]
    token = await get_valid_token(req.ml_account_index)
    tn = state["tn_account"]
    results = []
    for item_id in req.item_ids:
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(f"{ML_BASE}/items/{item_id}?access_token={token}")
                product = r.json()
                if "error" in product:
                    results.append({"id": item_id, "ok": False, "msg": product.get("message", "Error ML")})
                    continue
                dr = await client.get(f"{ML_BASE}/items/{item_id}/description?access_token={token}")
                description = dr.json().get("plain_text", "")
                variations = product.get("variations", [])
                if variations:
                    tn_variants = []
                    for v in variations:
                        attrs = {a["name"]: a["value_name"] for a in v.get("attribute_combinations", [])}
                        attr_str = " / ".join(f"{k}: {val}" for k, val in attrs.items())
                        tn_variants.append({
                            "price": str(v.get("price") or product.get("price", 0)),
                            "stock_management": True,
                            "stock": v.get("available_quantity", 0),
                            "values": [{"es": val} for val in attrs.values()] if attrs else []
                        })
                    payload = {
                        "name": {"es": product["title"]},
                        "description": {"es": description or product["title"]},
                        "published": True,
                        "variants": tn_variants,
                        "images": [{"src": p["url"]} for p in (product.get("pictures") or [])[:5]]
                    }
                else:
                    payload = {
                        "name": {"es": product["title"]},
                        "description": {"es": description or product["title"]},
                        "published": True,
                        "variants": [{"price": str(product.get("price", 0)),
                                      "stock_management": True,
                                      "stock": product.get("available_quantity", 0)}],
                        "images": [{"src": p["url"]} for p in (product.get("pictures") or [])[:5]]
                    }
                pr = await client.post(f"{TN_BASE}/{tn['store_id']}/products",
                                       headers=tn_headers(tn["token"]), json=payload)
                resp = pr.json()
                ok = pr.status_code in (200, 201)
                msg = "Publicado" if ok else (resp.get("description") or resp.get("message") or f"Error {pr.status_code}")
                results.append({"id": item_id, "title": product.get("title", ""), "ok": ok, "msg": msg})
                state["sync_log"].append({"ts": int(time.time()), "action": "publish",
                                          "product": product.get("title", ""), "status": "ok" if ok else "error"})
                save_data(state)
            await asyncio.sleep(0.3)
        except Exception as e:
            results.append({"id": item_id, "ok": False, "msg": str(e)})
    return {"results": results}

@app.post("/api/sync/manual")
async def sync_manual(_: str = Depends(get_session)):
    """Sync all manually linked ML items to TN."""
    if not state["tn_account"].get("store_id"):
        raise HTTPException(400, detail="Tienda Nube no conectada.")
    tn = state["tn_account"]
    links = state.get("links", [])
    if not links:
        return {"results": [], "total": 0, "msg": "No hay enlaces manuales configurados."}
    results = []
    for link in links:
        acc_idx = link.get("ml_account_index", 0)
        if acc_idx >= len(state["ml_accounts"]):
            continue
        token = await get_valid_token(acc_idx)
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.get(f"{ML_BASE}/items/{link['ml_item_id']}?access_token={token}")
                ml_item = r.json()
                if "error" in ml_item:
                    results.append({"title": link["ml_item_id"], "ok": False, "action": ml_item.get("message", "Error ML")})
                    continue
                var_id = link.get("ml_variation_id")
                if var_id:
                    variation = next((v for v in ml_item.get("variations", []) if str(v["id"]) == str(var_id)), None)
                    price = str(variation.get("price") or ml_item.get("price", 0)) if variation else str(ml_item.get("price", 0))
                    stock = variation.get("available_quantity", 0) if variation else ml_item.get("available_quantity", 0)
                else:
                    price = str(ml_item.get("price", 0))
                    stock = ml_item.get("available_quantity", 0)
                tn_pid = link["tn_product_id"]
                tn_vid = link.get("tn_variant_id")
                if tn_vid:
                    r2 = await client.put(
                        f"{TN_BASE}/{tn['store_id']}/products/{tn_pid}/variants/{tn_vid}",
                        headers=tn_headers(tn["token"]),
                        json={"price": price, "stock": stock}
                    )
                else:
                    r2 = await client.get(f"{TN_BASE}/{tn['store_id']}/products/{tn_pid}",
                                          headers=tn_headers(tn["token"]))
                    tn_product = r2.json()
                    first_variant = (tn_product.get("variants") or [{}])[0]
                    if first_variant.get("id"):
                        r2 = await client.put(
                            f"{TN_BASE}/{tn['store_id']}/products/{tn_pid}/variants/{first_variant['id']}",
                            headers=tn_headers(tn["token"]),
                            json={"price": price, "stock": stock}
                        )
                ok = r2.status_code in (200, 201)
                results.append({"title": ml_item.get("title", link["ml_item_id"]), "ok": ok,
                                 "action": "actualizado" if ok else f"Error {r2.status_code}"})
                state["sync_log"].append({"ts": int(time.time()), "action": "sync",
                                          "product": ml_item.get("title", ""), "status": "ok" if ok else "error"})
            await asyncio.sleep(0.2)
        except Exception as e:
            results.append({"title": link["ml_item_id"], "ok": False, "action": str(e)})
    state["last_sync"] = int(time.time())
    save_data(state)
    return {"results": results, "total": len(results)}

@app.post("/api/duplicate")
async def duplicate_products(req: DuplicateRequest, _: str = Depends(get_session)):
    """Duplicate ML items from one account to another."""
    if req.from_account >= len(state["ml_accounts"]) or req.to_account >= len(state["ml_accounts"]):
        raise HTTPException(404, detail="Cuenta no encontrada.")
    from_token = await get_valid_token(req.from_account)
    to_token = await get_valid_token(req.to_account)
    results = []
    async with httpx.AsyncClient(timeout=30) as client:
        for item_id in req.item_ids:
            try:
                r = await client.get(f"{ML_BASE}/items/{item_id}?access_token={from_token}")
                item = r.json()
                if "error" in item:
                    results.append({"id": item_id, "ok": False, "msg": item.get("message", "Error")})
                    continue
                # Build new item payload
                payload = {
                    "title": item["title"],
                    "category_id": item.get("category_id", ""),
                    "price": item.get("price", 0),
                    "currency_id": item.get("currency_id", "ARS"),
                    "available_quantity": item.get("available_quantity", 0),
                    "listing_type_id": item.get("listing_type_id", "gold_special"),
                    "condition": item.get("condition", "new"),
                    "pictures": [{"source": p["url"]} for p in (item.get("pictures") or [])[:12]],
                    "attributes": item.get("attributes", []),
                }
                if item.get("variations"):
                    payload["variations"] = item["variations"]
                r2 = await client.post(f"{ML_BASE}/items?access_token={to_token}", json=payload)
                ok = r2.status_code in (200, 201)
                msg = "Duplicado" if ok else r2.json().get("message", f"Error {r2.status_code}")
                results.append({"id": item_id, "title": item.get("title", ""), "ok": ok, "msg": msg})
                await asyncio.sleep(0.5)
            except Exception as e:
                results.append({"id": item_id, "ok": False, "msg": str(e)})
    return {"results": results}

frontend_path = Path("frontend")
if frontend_path.exists():
    app.mount("/", StaticFiles(directory=str(frontend_path), html=True), name="frontend")
