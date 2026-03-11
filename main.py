from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import httpx
import asyncio
import json
import os
import time
import secrets
from pathlib import Path

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

ML_CLIENT_ID     = os.getenv("ML_CLIENT_ID", "4576804985048120")
ML_CLIENT_SECRET = os.getenv("ML_CLIENT_SECRET", "j0FhuZVrZ3XUhdZIsdddpGISWt39JuHY")
APP_URL          = os.getenv("APP_URL", "https://mltn-sync-production.up.railway.app")
ML_REDIRECT_URI  = f"{APP_URL}/auth/callback"
ADMIN_EMAIL      = os.getenv("ADMIN_EMAIL", "admin@sync.com")
ADMIN_PASSWORD   = os.getenv("ADMIN_PASSWORD", "sync1234")
ML_BASE = "https://api.mercadolibre.com"
TN_BASE = "https://api.tiendanube.com/v1"
SESSIONS = {}
DATA_FILE = "data.json"

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

def get_session(request: Request):
    token = request.headers.get("X-Session-Token")
    if not token or token not in SESSIONS or SESSIONS[token] < time.time():
        raise HTTPException(status_code=401, detail="No autorizado.")
    SESSIONS[token] = time.time() + 86400 * 7
    return token


@app.get("/test/{index}")
async def test_ml(index: int, token: str = ""):
    """Public test - pass token as query param"""
    if not token and index < len(state["ml_accounts"]):
        token = state["ml_accounts"][index].get("token", "")
    if not token:
        return {"error": "no token"}
    async with httpx.AsyncClient(timeout=15) as client:
        r1 = await client.get(f"{ML_BASE}/users/me")
        me = r1.json()
        user_id = str(me.get("id", ""))
        r2 = await client.get(f"{ML_BASE}/users/{user_id}/items/search?search_type=scan")
        scan = r2.json()
        r3 = await client.get(f"{ML_BASE}/users/{user_id}/items/search?limit=5&offset=0")
        normal = r3.json()
    return {
        "user_id": user_id,
        "nickname": me.get("nickname"),
        "scan_result": scan,
        "normal_result": normal
    }


@app.get("/diag")
async def diag():
    """Public diagnostic - shows ML API response"""
    if not state["ml_accounts"]:
        return {"error": "No hay cuentas conectadas"}
    acc = state["ml_accounts"][0]
    token = acc.get("token", "")
    result = {}
    async with httpx.AsyncClient(timeout=15) as client:
        # Test with Bearer header
        r1 = await client.get(f"{ML_BASE}/users/me", headers={"Authorization": f"Bearer {token}"})
        result["bearer_status"] = r1.status_code
        result["bearer_body"] = r1.text[:500]
        # Test with access_token param
        r2 = await client.get(f"{ML_BASE}/users/me?access_token={token}")
        result["param_status"] = r2.status_code
        result["param_body"] = r2.text[:500]
        result["token_preview"] = token[:20] + "..." if token else "EMPTY"
        result["token_expiry"] = acc.get("token_expiry", 0)
        result["token_expired"] = __import__("time").time() > acc.get("token_expiry", 0)
    return result

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/api/login")
async def login(request: Request):
    body = await request.json()
    email = body.get("email", "").strip().lower()
    password = body.get("password", "")
    if email != ADMIN_EMAIL.lower() or password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Email o contraseña incorrectos.")
    token = secrets.token_hex(32)
    SESSIONS[token] = time.time() + 86400 * 7
    return {"token": token, "ok": True}

@app.post("/api/logout")
def logout(session: str = Depends(get_session)):
    SESSIONS.pop(session, None)
    return {"ok": True}

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
        ur = await client.get(f"{ML_BASE}/users/{user_id}")
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

def ml_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}

async def ml_get_all_items(user_id: str, token: str) -> list:
    all_ids = []
    hdrs = ml_headers(token)
    # Verify token using Authorization header
    async with httpx.AsyncClient(timeout=15) as client:
        me_r = await client.get(f"{ML_BASE}/users/me", headers=hdrs)
        if me_r.status_code != 200:
            raise HTTPException(status_code=401, detail=f"Token invalido (status {me_r.status_code}). Reconectá la cuenta.")
        try:
            me = me_r.json()
        except Exception:
            raise HTTPException(status_code=401, detail="ML no respondió. Reconectá la cuenta.")
        if "id" not in me:
            raise HTTPException(status_code=401, detail=f"Token invalido: {me.get('message','?')}. Reconectá la cuenta.")
        real_user_id = str(me["id"])
    # Scan for large catalogs
    async with httpx.AsyncClient(timeout=30) as client:
        scroll_id = None
        for _ in range(100):
            if scroll_id:
                url = f"{ML_BASE}/users/{real_user_id}/items/search?search_type=scan&scroll_id={scroll_id}"
            else:
                url = f"{ML_BASE}/users/{real_user_id}/items/search?search_type=scan"
            r = await client.get(url, headers=hdrs)
            if r.status_code != 200:
                break
            data = r.json()
            if "error" in data:
                break
            ids = data.get("results", [])
            if not ids:
                break
            all_ids.extend(ids)
            scroll_id = data.get("scroll_id")
            if not scroll_id:
                break
            await asyncio.sleep(0.15)
    # Fallback: offset pagination
    if not all_ids:
        async with httpx.AsyncClient(timeout=30) as client:
            offset = 0
            while True:
                r = await client.get(f"{ML_BASE}/users/{real_user_id}/items/search?limit=50&offset={offset}", headers=hdrs)
                if r.status_code != 200:
                    if offset == 0:
                        raise HTTPException(status_code=400, detail=f"Error ML {r.status_code}: {r.text[:300]}")
                    break
                data = r.json()
                if "error" in data:
                    if offset == 0:
                        raise HTTPException(status_code=400, detail=f"Error ML: {data.get('message', str(data))}")
                    break
                ids = data.get("results", [])
                if not ids:
                    break
                all_ids.extend(ids)
                total = data.get("paging", {}).get("total", 0)
                offset += 50
                if offset >= total:
                    break
                await asyncio.sleep(0.15)
    if not all_ids:
        return []
    products = []
    async with httpx.AsyncClient(timeout=60) as client:
        for i in range(0, len(all_ids), 20):
            batch = all_ids[i:i+20]
            r = await client.get(f"{ML_BASE}/items?ids={','.join(batch)}", headers=ml_headers(token))
            for item in r.json():
                if item.get("code") == 200:
                    body = item["body"]
                    variations = body.get("variations", [])
                    body["_has_variations"] = len(variations) > 0
                    body["_variation_count"] = len(variations)
                    for v in variations:
                        v["_attrs"] = {a["name"]: a["value_name"] for a in v.get("attribute_combinations", [])}
                    products.append(body)
            await asyncio.sleep(0.05)
    return products

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
        raise HTTPException(status_code=404)
    removed = state["ml_accounts"].pop(index)
    save_data(state)
    return {"ok": True, "removed": removed["name"]}

@app.post("/api/tn/connect")
async def connect_tn(request: Request, _: str = Depends(get_session)):
    body = await request.json()
    state["tn_account"] = {"store_id": body.get("store_id",""), "token": body.get("token","")}
    save_data(state)
    return {"ok": True}

@app.get("/api/ml/{index}/debug")
async def debug_ml(index: int, _: str = Depends(get_session)):
    if index < 0 or index >= len(state["ml_accounts"]):
        raise HTTPException(status_code=404)
    acc = state["ml_accounts"][index]
    token = await get_valid_token(index)
    async with httpx.AsyncClient(timeout=15) as client:
        r1 = await client.get(f"{ML_BASE}/users/me")
        me = r1.json()
        r2 = await client.get(f"{ML_BASE}/users/{acc['user_id']}/items/search?limit=10&offset=0")
        search = r2.json()
    return {"saved_user_id": acc["user_id"], "token_expired": time.time() > acc.get("token_expiry", 0), "me": me, "search": search}

@app.get("/api/ml/{index}/products")
async def get_ml_products(index: int, _: str = Depends(get_session)):
    if index < 0 or index >= len(state["ml_accounts"]):
        raise HTTPException(status_code=404)
    acc = state["ml_accounts"][index]
    token = await get_valid_token(index)
    products = await ml_get_all_items(acc["user_id"], token)
    return {"products": products, "total": len(products)}

@app.get("/api/tn/products")
async def get_tn_products(_: str = Depends(get_session)):
    if not state["tn_account"].get("store_id"):
        raise HTTPException(status_code=400, detail="Tienda Nube no conectada.")
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
async def add_link(request: Request, _: str = Depends(get_session)):
    req = await request.json()
    links = state.get("links", [])
    ml_item_id = req.get("ml_item_id")
    ml_variation_id = req.get("ml_variation_id")
    link_key = ml_item_id + ("_" + ml_variation_id if ml_variation_id else "")
    links = [l for l in links if (l["ml_item_id"] + ("_" + l.get("ml_variation_id","") if l.get("ml_variation_id") else "")) != link_key]
    links.append({
        "ml_item_id": ml_item_id,
        "ml_variation_id": ml_variation_id,
        "ml_account_index": req.get("ml_account_index", 0),
        "tn_product_id": req.get("tn_product_id"),
        "tn_variant_id": req.get("tn_variant_id")
    })
    state["links"] = links
    save_data(state)
    return {"ok": True}

@app.post("/api/links/remove")
async def remove_link(request: Request, _: str = Depends(get_session)):
    req = await request.json()
    ml_item_id = req.get("ml_item_id")
    ml_variation_id = req.get("ml_variation_id")
    link_key = ml_item_id + ("_" + ml_variation_id if ml_variation_id else "")
    state["links"] = [l for l in state.get("links", [])
                      if (l["ml_item_id"] + ("_" + l.get("ml_variation_id","") if l.get("ml_variation_id") else "")) != link_key]
    save_data(state)
    return {"ok": True}

@app.post("/api/publish")
async def publish_products(request: Request, _: str = Depends(get_session)):
    req = await request.json()
    item_ids = req.get("item_ids", [])
    ml_account_index = req.get("ml_account_index", 0)
    if not state["tn_account"].get("store_id"):
        raise HTTPException(status_code=400, detail="Tienda Nube no conectada.")
    token = await get_valid_token(ml_account_index)
    tn = state["tn_account"]
    results = []
    for item_id in item_ids:
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(f"{ML_BASE}/items/{item_id}", headers=ml_headers(token))
                product = r.json()
                if "error" in product:
                    results.append({"id": item_id, "ok": False, "msg": product.get("message","Error ML")})
                    continue
                dr = await client.get(f"{ML_BASE}/items/{item_id}/description", headers=ml_headers(token))
                description = dr.json().get("plain_text", "")
                variations = product.get("variations", [])
                if variations:
                    tn_variants = []
                    for v in variations:
                        attrs = {a["name"]: a["value_name"] for a in v.get("attribute_combinations", [])}
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
                        "variants": [{"price": str(product.get("price",0)), "stock_management": True, "stock": product.get("available_quantity",0)}],
                        "images": [{"src": p["url"]} for p in (product.get("pictures") or [])[:5]]
                    }
                pr = await client.post(f"{TN_BASE}/{tn['store_id']}/products",
                                       headers=tn_headers(tn["token"]), json=payload)
                ok = pr.status_code in (200, 201)
                resp = pr.json()
                msg = "Publicado" if ok else (resp.get("description") or resp.get("message") or f"Error {pr.status_code}")
                results.append({"id": item_id, "title": product.get("title",""), "ok": ok, "msg": msg})
                state["sync_log"].append({"ts": int(time.time()), "action": "publish", "product": product.get("title",""), "status": "ok" if ok else "error"})
                save_data(state)
            await asyncio.sleep(0.3)
        except Exception as e:
            results.append({"id": item_id, "ok": False, "msg": str(e)})
    return {"results": results}

@app.post("/api/sync/manual")
async def sync_manual(_: str = Depends(get_session)):
    if not state["tn_account"].get("store_id"):
        raise HTTPException(status_code=400, detail="Tienda Nube no conectada.")
    tn = state["tn_account"]
    links = state.get("links", [])
    if not links:
        return {"results": [], "total": 0, "msg": "No hay enlaces configurados."}
    results = []
    for link in links:
        acc_idx = link.get("ml_account_index", 0)
        if acc_idx >= len(state["ml_accounts"]):
            continue
        token = await get_valid_token(acc_idx)
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.get(f"{ML_BASE}/items/{link['ml_item_id']}", headers=ml_headers(token))
                ml_item = r.json()
                if "error" in ml_item:
                    results.append({"title": link["ml_item_id"], "ok": False, "action": ml_item.get("message","Error ML")})
                    continue
                var_id = link.get("ml_variation_id")
                if var_id:
                    variation = next((v for v in ml_item.get("variations",[]) if str(v["id"])==str(var_id)), None)
                    price = str(variation.get("price") or ml_item.get("price",0)) if variation else str(ml_item.get("price",0))
                    stock = variation.get("available_quantity",0) if variation else ml_item.get("available_quantity",0)
                else:
                    price = str(ml_item.get("price",0))
                    stock = ml_item.get("available_quantity",0)
                tn_pid = link["tn_product_id"]
                tn_vid = link.get("tn_variant_id")
                if tn_vid:
                    r2 = await client.put(f"{TN_BASE}/{tn['store_id']}/products/{tn_pid}/variants/{tn_vid}",
                                          headers=tn_headers(tn["token"]), json={"price": price, "stock": stock})
                else:
                    r2 = await client.get(f"{TN_BASE}/{tn['store_id']}/products/{tn_pid}", headers=tn_headers(tn["token"]))
                    tn_product = r2.json()
                    first_variant = (tn_product.get("variants") or [{}])[0]
                    if first_variant.get("id"):
                        r2 = await client.put(f"{TN_BASE}/{tn['store_id']}/products/{tn_pid}/variants/{first_variant['id']}",
                                              headers=tn_headers(tn["token"]), json={"price": price, "stock": stock})
                ok = r2.status_code in (200, 201)
                results.append({"title": ml_item.get("title", link["ml_item_id"]), "ok": ok,
                                 "action": "actualizado" if ok else f"Error {r2.status_code}"})
                state["sync_log"].append({"ts": int(time.time()), "action": "sync", "product": ml_item.get("title",""), "status": "ok" if ok else "error"})
            await asyncio.sleep(0.2)
        except Exception as e:
            results.append({"title": link["ml_item_id"], "ok": False, "action": str(e)})
    state["last_sync"] = int(time.time())
    save_data(state)
    return {"results": results, "total": len(results)}

@app.post("/api/duplicate")
async def duplicate_products(request: Request, _: str = Depends(get_session)):
    req = await request.json()
    item_ids = req.get("item_ids", [])
    from_account = req.get("from_account", 0)
    to_account = req.get("to_account", 1)
    if from_account >= len(state["ml_accounts"]) or to_account >= len(state["ml_accounts"]):
        raise HTTPException(status_code=404, detail="Cuenta no encontrada.")
    from_token = await get_valid_token(from_account)
    to_token = await get_valid_token(to_account)
    results = []
    async with httpx.AsyncClient(timeout=30) as client:
        for item_id in item_ids:
            try:
                r = await client.get(f"{ML_BASE}/items/{item_id}", headers=ml_headers(from_token))
                item = r.json()
                if "error" in item:
                    results.append({"id": item_id, "ok": False, "msg": item.get("message","Error")})
                    continue
                payload = {
                    "title": item["title"],
                    "category_id": item.get("category_id",""),
                    "price": item.get("price",0),
                    "currency_id": item.get("currency_id","ARS"),
                    "available_quantity": item.get("available_quantity",0),
                    "listing_type_id": item.get("listing_type_id","gold_special"),
                    "condition": item.get("condition","new"),
                    "pictures": [{"source": p["url"]} for p in (item.get("pictures") or [])[:12]],
                    "attributes": item.get("attributes",[]),
                }
                if item.get("variations"):
                    payload["variations"] = item["variations"]
                r2 = await client.post(f"{ML_BASE}/items", headers=ml_headers(to_token), json=payload)
                ok = r2.status_code in (200, 201)
                msg = "Duplicado" if ok else r2.json().get("message", f"Error {r2.status_code}")
                results.append({"id": item_id, "title": item.get("title",""), "ok": ok, "msg": msg})
                await asyncio.sleep(0.5)
            except Exception as e:
                results.append({"id": item_id, "ok": False, "msg": str(e)})
    return {"results": results}


@app.get("/test-ml/{user_id}/{token}")
async def test_ml(user_id: str, token: str):
    """Public test - shows raw ML response"""
    async with httpx.AsyncClient(timeout=15) as client:
        r1 = await client.get(f"{ML_BASE}/users/me")
        r2 = await client.get(f"{ML_BASE}/users/{user_id}/items/search?limit=5&offset=0")
        r3 = await client.get(f"{ML_BASE}/users/{user_id}/items/search?search_type=scan")
    return {
        "me": r1.json(),
        "search_offset": r2.json(),
        "search_scan": r3.json()
    }

frontend_path = Path("frontend")
if frontend_path.exists():
    app.mount("/", StaticFiles(directory=str(frontend_path), html=True), name="frontend")
