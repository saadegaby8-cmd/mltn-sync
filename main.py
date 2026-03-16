from fastapi import FastAPI, HTTPException, Request, Depends, BackgroundTasks
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import httpx, asyncio, json, os, time, secrets
from pathlib import Path

async def token_refresh_loop():
    """Refresca tokens de ML automáticamente cada 5 horas"""
    while True:
        await asyncio.sleep(5 * 3600)  # esperar 5 horas
        for i, acc in enumerate(ST.get("accounts", [])):
            try:
                if acc.get("refresh"):
                    async with httpx.AsyncClient(timeout=15) as c:
                        r = await c.post("https://api.mercadolibre.com/oauth/token",
                            data={"grant_type":"refresh_token","client_id":ML_APP_ID,
                                  "client_secret":ML_SECRET,"refresh_token":acc["refresh"]},
                            headers={"Content-Type":"application/x-www-form-urlencoded"})
                        td = r.json()
                    if "access_token" in td:
                        acc["token"] = td["access_token"]
                        acc["refresh"] = td.get("refresh_token", acc["refresh"])
                        acc["expiry"] = time.time() + td.get("expires_in", 21600) - 300
                        acc["token_ok"] = True
                        save_state()
                        print(f"Token refreshed OK for account {i}: {acc.get('name','')}")
                    else:
                        acc["token_ok"] = False
                        acc["expiry"] = 0
                        save_state()
                        print(f"Token refresh FAILED for account {i}: {td}")
            except Exception as e:
                print(f"Token refresh error account {i}: {e}")

@asynccontextmanager
async def lifespan(app):
    asyncio.create_task(token_refresh_loop())
    yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

ML_APP_ID     = os.getenv("ML_CLIENT_ID", "4576804985048120")
ML_SECRET     = os.getenv("ML_CLIENT_SECRET", "j0FhuZVrZ3XUhdZIsdddpGISWt39JuHY")
APP_URL       = os.getenv("APP_URL", "https://mltn-sync-production.up.railway.app")
REDIRECT_URI  = f"{APP_URL}/auth/callback"
ADMIN_EMAIL   = os.getenv("ADMIN_EMAIL", "admin@sync.com")
ADMIN_PASS    = os.getenv("ADMIN_PASSWORD", "sync1234")
ML_API        = "https://api.mercadolibre.com"

SESSIONS = {}

def get_redis():
    url = os.getenv("REDIS_URL", "")
    if not url:
        return None
    try:
        import redis
        if url.startswith("rediss://"):
            r = redis.from_url(url, decode_responses=True, socket_timeout=5,
                               ssl_cert_reqs=None)
        else:
            r = redis.from_url(url, decode_responses=True, socket_timeout=5)
        r.ping()
        return r
    except Exception as e:
        print(f"Redis error: {e}")
        return None

def load_state():
    r = get_redis()
    if r:
        try:
            raw = r.get("mltn:state")
            if raw:
                return json.loads(raw)
        except:
            pass
    if Path("state.json").exists():
        return json.loads(Path("state.json").read_text())
    return {"accounts": [], "tn": {}, "log": [], "links": []}

def save_state():
    r = get_redis()
    data = json.dumps(ST)
    if r:
        try:
            r.set("mltn:state", data)
            return
        except:
            pass
    Path("state.json").write_text(data)

try:
    ST = load_state()
except:
    ST = {"accounts": [], "tn": {}, "log": [], "links": []}
if "links" not in ST: ST["links"] = []
if "accounts" not in ST: ST["accounts"] = []

def auth(req: Request):
    t = req.headers.get("X-Session-Token", "")
    if not t or t not in SESSIONS or SESSIONS[t] < time.time():
        raise HTTPException(401, "No autorizado.")
    SESSIONS[t] = time.time() + 86400 * 7
    return t

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/api/login")
async def login(req: Request):
    b = await req.json()
    if b.get("email","").lower() != ADMIN_EMAIL.lower() or b.get("password","") != ADMIN_PASS:
        raise HTTPException(401, "Email o contrasena incorrectos.")
    t = secrets.token_hex(32)
    SESSIONS[t] = time.time() + 86400 * 7
    return {"token": t, "ok": True}

@app.post("/api/logout")
def logout(s=Depends(auth)):
    SESSIONS.pop(s, None)
    return {"ok": True}

@app.get("/auth/login")
def ml_login():
    return RedirectResponse(
        f"https://auth.mercadolibre.com.ar/authorization"
        f"?response_type=code&client_id={ML_APP_ID}&redirect_uri={REDIRECT_URI}"
    )

@app.get("/auth/callback")
async def ml_callback(code: str = None, error: str = None):
    if not code:
        return RedirectResponse(f"{APP_URL}/?error=auth_failed")
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post("https://api.mercadolibre.com/oauth/token",
            data={"grant_type":"authorization_code","client_id":ML_APP_ID,
                  "client_secret":ML_SECRET,"code":code,"redirect_uri":REDIRECT_URI},
            headers={"Content-Type":"application/x-www-form-urlencoded"})
        td = r.json()
    if "access_token" not in td:
        return RedirectResponse(f"{APP_URL}/?error=token_failed")
    token = td["access_token"]
    uid = str(td.get("user_id",""))
    async with httpx.AsyncClient(timeout=10) as c:
        ur = await c.get(f"{ML_API}/users/{uid}", headers={"Authorization":f"Bearer {token}"})
        info = ur.json()
    name = info.get("nickname", f"Cuenta {len(ST['accounts'])+1}")
    for acc in ST["accounts"]:
        if acc["uid"] == uid:
            acc.update({"token":token,"refresh":td.get("refresh_token",""),
                        "expiry":time.time()+td.get("expires_in",21600)-300})
            save_state()
            return RedirectResponse(f"{APP_URL}/?success=reconnected")
    if len(ST["accounts"]) >= 4:
        return RedirectResponse(f"{APP_URL}/?error=max_accounts")
    ST["accounts"].append({"name":name,"uid":uid,"token":token,
                           "refresh":td.get("refresh_token",""),
                           "expiry":time.time()+td.get("expires_in",21600)-300})
    save_state()
    return RedirectResponse(f"{APP_URL}/?success=connected")

async def fresh_token(i: int) -> str:
    acc = ST["accounts"][i]
    if time.time() > acc.get("expiry",0) and acc.get("refresh"):
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.post("https://api.mercadolibre.com/oauth/token",
                    data={"grant_type":"refresh_token","client_id":ML_APP_ID,
                          "client_secret":ML_SECRET,"refresh_token":acc["refresh"]},
                    headers={"Content-Type":"application/x-www-form-urlencoded"})
                td = r.json()
            if "access_token" in td:
                acc["token"] = td["access_token"]
                acc["refresh"] = td.get("refresh_token", acc["refresh"])
                acc["expiry"] = time.time() + td.get("expires_in",21600) - 300
                acc["token_ok"] = True
                save_state()
            else:
                # Refresh falló — marcar como vencido
                acc["token_ok"] = False
                acc["expiry"] = 0
                save_state()
        except Exception as e:
            acc["token_ok"] = False
            save_state()
    return acc["token"]

@app.get("/api/state")
def get_state(_=Depends(auth)):
    return {
        "ml_accounts": [{"name":a["name"],"user_id":a["uid"],
                         "token_ok": time.time() < a.get("expiry",0)} for a in ST["accounts"]],
        "tn_connected": bool(ST["tn"].get("store_id")),
        "tn_store_id": ST["tn"].get("store_id",""),
        "last_sync": None,
        "sync_log": ST["log"][-50:],
        "links": ST["links"]
    }

@app.delete("/api/ml/{i}")
def remove_ml(i: int, _=Depends(auth)):
    if i < 0 or i >= len(ST["accounts"]):
        raise HTTPException(404)
    ST["accounts"].pop(i)
    save_state()
    return {"ok": True}

@app.post("/api/tn/connect")
async def connect_tn(req: Request, _=Depends(auth)):
    b = await req.json()
    ST["tn"] = {"store_id": b.get("store_id",""), "token": b.get("token","")}
    save_state()
    return {"ok": True}

SYNC_RUNNING = {}

def redis_products_key(uid): return f"mltn:products:{uid}"
def redis_status_key(uid): return f"mltn:sync_status:{uid}"

def get_cached_products(uid):
    r = get_redis()
    if r:
        try:
            raw = r.get(redis_products_key(uid))
            if raw:
                return json.loads(raw)
        except: pass
    return None

def set_cached_products(uid, products):
    r = get_redis()
    if r:
        try:
            r.set(redis_products_key(uid), json.dumps(products))
            r.set(redis_status_key(uid), json.dumps({"status":"done","total":len(products),"ts":int(time.time())}))
        except: pass

def set_sync_status(uid, status, total=0, fetched=0):
    r = get_redis()
    if r:
        try:
            r.set(redis_status_key(uid), json.dumps({"status":status,"total":total,"fetched":fetched,"ts":int(time.time())}))
        except: pass

def get_sync_status(uid):
    r = get_redis()
    if r:
        try:
            raw = r.get(redis_status_key(uid))
            if raw: return json.loads(raw)
        except: pass
    return None

async def do_sync_products(i: int, uid: str, token: str):
    hdrs = {"Authorization": f"Bearer {token}"}
    set_sync_status(uid, "fetching_ids", total=0, fetched=0)
    all_ids = []
    try:
        # Usar scroll scan solo para items activos con stock
        async with httpx.AsyncClient(timeout=60) as c:
            scroll_id = None
            for _ in range(1000):
                url = f"{ML_API}/users/{uid}/items/search?search_type=scan&limit=100&status=active"
                if scroll_id:
                    url += f"&scroll_id={scroll_id}"
                try:
                    r = await c.get(url, headers=hdrs)
                    if r.status_code == 429:
                        await asyncio.sleep(60)
                        r = await c.get(url, headers=hdrs)
                    if r.status_code != 200:
                        break
                    d = r.json()
                    ids = d.get("results", [])
                    if not ids:
                        break
                    all_ids.extend(ids)
                    all_ids = list(dict.fromkeys(all_ids))  # deduplicar manteniendo orden
                    set_sync_status(uid, "fetching_ids", total=len(all_ids), fetched=0)
                    scroll_id = d.get("scroll_id")
                    if not scroll_id:
                        break
                    await asyncio.sleep(0.8)
                except Exception:
                    break

        if not all_ids:
            set_sync_status(uid, "error: no se encontraron productos")
            SYNC_RUNNING.pop(uid, None)
            return

        # Esperar antes de empezar a bajar detalles
        await asyncio.sleep(10)

        # Obtener detalles en batches de 20
        set_sync_status(uid, "fetching_details", total=len(all_ids), fetched=0)

        # Cargar productos ya descargados para poder retomar
        existing = get_cached_products(uid) or []
        existing_ids = {p["id"] for p in existing}
        products = list(existing)
        pending_ids = [id for id in all_ids if id not in existing_ids]
        set_sync_status(uid, "fetching_details", total=len(all_ids), fetched=len(products))

        async with httpx.AsyncClient(timeout=60) as c:
            for x in range(0, len(pending_ids), 20):
                batch = pending_ids[x:x+20]
                for attempt in range(5):
                    try:
                        r = await c.get(f"{ML_API}/items?ids={','.join(batch)}", headers=hdrs)
                        if r.status_code == 429:
                            wait = 60 * (attempt + 1)
                            await asyncio.sleep(wait)
                            continue
                        if r.status_code == 200:
                            for item in r.json():
                                if item.get("code") == 200:
                                    b = item["body"]
                                    for v in b.get("variations",[]):
                                        v["_attrs"] = {a["name"]:a["value_name"] for a in v.get("attribute_combinations",[])}
                                    b["_has_variations"] = len(b.get("variations",[])) > 0
                                    b["_variation_count"] = len(b.get("variations",[]))
                                    products.append(b)
                        break
                    except Exception:
                        await asyncio.sleep(5)
                set_sync_status(uid, "fetching_details", total=len(all_ids), fetched=len(products))
                if len(products) % 100 == 0 and len(products) > 0:
                    set_cached_products(uid, products)
                await asyncio.sleep(5)

        set_cached_products(uid, products)
        set_sync_status(uid, "done", total=len(products), fetched=len(products))

    except Exception as e:
        set_sync_status(uid, f"error: {str(e)}")
    finally:
        SYNC_RUNNING.pop(uid, None)

@app.post("/api/ml/{i}/sync")
async def start_sync(i: int, background_tasks: BackgroundTasks, _=Depends(auth)):
    if i < 0 or i >= len(ST["accounts"]):
        raise HTTPException(404)
    acc = ST["accounts"][i]
    uid = acc["uid"]
    if uid in SYNC_RUNNING:
        return {"ok": False, "msg": "Ya esta sincronizando"}
    token = await fresh_token(i)
    SYNC_RUNNING[uid] = True
    background_tasks.add_task(do_sync_products, i, uid, token)
    return {"ok": True, "msg": "Sincronizacion iniciada"}

@app.get("/api/ml/{i}/sync/status")
def sync_status(i: int, _=Depends(auth)):
    if i < 0 or i >= len(ST["accounts"]):
        raise HTTPException(404)
    uid = ST["accounts"][i]["uid"]
    status = get_sync_status(uid)
    running = uid in SYNC_RUNNING
    return {"running": running, "status": status}

@app.get("/api/ml/{i}/products")
async def get_products(i: int, page: int = 1, limit: int = 50,
                       status: str = "all", search: str = "", _=Depends(auth)):
    if i < 0 or i >= len(ST["accounts"]):
        raise HTTPException(404)
    uid = ST["accounts"][i]["uid"]
    products = get_cached_products(uid)
    if products is None:
        return {"products": [], "total": 0, "synced": False,
                "msg": "Productos no sincronizados. Presiona Sincronizar."}
    if status != "all":
        products = [p for p in products if p.get("status","") == status]
    if search:
        s = search.lower()
        products = [p for p in products if s in p.get("title","").lower()]
    total = len(products)
    if limit >= 9999:
        return {"products": products, "items": products, "total": total, "synced": True, "page": 1, "limit": total}
    start = (page-1)*limit
    page_products = products[start:start+limit]
    return {"products": page_products, "items": page_products, "total": total, "synced": True, "page": page, "limit": limit}

@app.get("/api/ml/{i}/health")
async def get_items_health(i: int, ids: str = "", _=Depends(auth)):
    """Obtener health/calidad de un batch de items"""
    if i < 0 or i >= len(ST["accounts"]):
        raise HTTPException(404)
    if not ids:
        return {"health": {}}
    token = await fresh_token(i)
    id_list = ids.split(",")[:20]
    health_map = {}
    async with httpx.AsyncClient(timeout=20) as c:
        for item_id in id_list:
            try:
                r = await c.get(f"{ML_API}/items/{item_id}/health",
                               headers={"Authorization": f"Bearer {token}"})
                if r.status_code == 200:
                    health_map[item_id] = r.json().get("health", None)
            except Exception:
                pass
            await asyncio.sleep(0.2)
    return {"health": health_map}

@app.get("/api/tn/products")
async def get_tn_products(_=Depends(auth)):
    if not ST["tn"].get("store_id"):
        raise HTTPException(400, "TN no conectada.")
    tn = ST["tn"]
    hdrs = {"Authentication":f"bearer {tn['token']}","Content-Type":"application/json"}
    all_p = []
    async with httpx.AsyncClient(timeout=30) as c:
        for pg in range(1, 50):
            r = await c.get(f"https://api.tiendanube.com/v1/{tn['store_id']}/products?page={pg}&per_page=50", headers=hdrs)
            d = r.json()
            if not isinstance(d, list) or not d:
                break
            all_p.extend(d)
            if len(d) < 50:
                break
            await asyncio.sleep(0.1)
    return {"products": all_p, "total": len(all_p)}

@app.post("/api/links/add")
async def add_link(req: Request, _=Depends(auth)):
    b = await req.json()
    key = b["ml_item_id"] + ("_"+b["ml_variation_id"] if b.get("ml_variation_id") else "")
    ST["links"] = [l for l in ST["links"]
                   if (l["ml_item_id"]+("_"+l.get("ml_variation_id","") if l.get("ml_variation_id") else "")) != key]
    ST["links"].append(b)
    save_state()
    return {"ok": True}

@app.post("/api/links/remove")
async def remove_link(req: Request, _=Depends(auth)):
    b = await req.json()
    key = b["ml_item_id"] + ("_"+b.get("ml_variation_id","") if b.get("ml_variation_id") else "")
    ST["links"] = [l for l in ST["links"]
                   if (l["ml_item_id"]+("_"+l.get("ml_variation_id","") if l.get("ml_variation_id") else "")) != key]
    save_state()
    return {"ok": True}

@app.post("/api/sync/manual")
async def sync(_=Depends(auth)):
    if not ST["tn"].get("store_id"):
        raise HTTPException(400, "TN no conectada.")
    tn = ST["tn"]
    tn_hdrs = {"Authentication":f"bearer {tn['token']}","Content-Type":"application/json"}
    results = []
    for link in ST["links"]:
        idx = link.get("ml_account_index", 0)
        if idx >= len(ST["accounts"]):
            continue
        token = await fresh_token(idx)
        ml_hdrs = {"Authorization": f"Bearer {token}"}
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(f"{ML_API}/items/{link['ml_item_id']}", headers=ml_hdrs)
                item = r.json()
                var_id = link.get("ml_variation_id")
                if var_id:
                    v = next((x for x in item.get("variations",[]) if str(x["id"])==str(var_id)), None)
                    price = str(v.get("price", item.get("price",0))) if v else str(item.get("price",0))
                    stock = v.get("available_quantity",0) if v else item.get("available_quantity",0)
                else:
                    price = str(item.get("price",0))
                    stock = item.get("available_quantity",0)
                pid = link["tn_product_id"]
                vid = link.get("tn_variant_id")
                if not vid:
                    rp = await c.get(f"https://api.tiendanube.com/v1/{tn['store_id']}/products/{pid}", headers=tn_hdrs)
                    vid = (rp.json().get("variants") or [{}])[0].get("id")
                if vid:
                    r2 = await c.put(f"https://api.tiendanube.com/v1/{tn['store_id']}/products/{pid}/variants/{vid}",
                                     headers=tn_hdrs, json={"price":price,"stock":stock})
                    ok = r2.status_code in (200,201)
                else:
                    ok = False
                results.append({"title": item.get("title",""), "ok": ok})
                ST["log"].append({"ts":int(time.time()),"action":"sync","product":item.get("title",""),"status":"ok" if ok else "error"})
            await asyncio.sleep(0.2)
        except Exception as e:
            results.append({"title": link["ml_item_id"], "ok": False, "action": str(e)})
    save_state()
    return {"results": results}

@app.post("/api/publish")
async def publish(req: Request, _=Depends(auth)):
    b = await req.json()
    item_ids = b.get("item_ids", [])
    idx = b.get("ml_account_index", 0)
    target = b.get("target", "tn")  # "tn" o "ml"
    target_ml_idx = b.get("target_ml_index", 0)

    # Publicar en ML (duplicar a otra cuenta)
    if target == "ml":
        if target_ml_idx >= len(ST["accounts"]):
            raise HTTPException(400, "Cuenta ML destino no existe.")
        from_t = await fresh_token(idx)
        to_t = await fresh_token(target_ml_idx)
        results = []
        async with httpx.AsyncClient(timeout=30) as c:
            for iid in item_ids:
                try:
                    r = await c.get(f"{ML_API}/items/{iid}", headers={"Authorization":f"Bearer {from_t}"})
                    item = r.json()
                    payload = {"title":item["title"],"category_id":item.get("category_id",""),
                               "price":item.get("price",0),"currency_id":item.get("currency_id","ARS"),
                               "available_quantity":item.get("available_quantity",0),
                               "listing_type_id":item.get("listing_type_id","gold_special"),
                               "condition":item.get("condition","new"),
                               "pictures":[{"source":p["url"]} for p in (item.get("pictures") or [])[:12]],
                               "attributes":item.get("attributes",[])}
                    if item.get("variations"):
                        payload["variations"] = item["variations"]
                    r2 = await c.post(f"{ML_API}/items", headers={"Authorization":f"Bearer {to_t}"}, json=payload)
                    ok = r2.status_code in (200,201)
                    results.append({"id":iid,"title":item.get("title",""),"ok":ok,
                                    "msg":"Publicado en ML" if ok else r2.json().get("message","Error")})
                    ST["log"].append({"ts":int(time.time()),"action":"publish_ml","product":item.get("title",""),"status":"ok" if ok else "error"})
                    await asyncio.sleep(0.5)
                except Exception as e:
                    results.append({"id":iid,"ok":False,"msg":str(e)})
        save_state()
        return {"results": results}

    # Publicar en TiendaNube
    if not ST["tn"].get("store_id"):
        raise HTTPException(400, "TN no conectada.")
    token = await fresh_token(idx)
    ml_hdrs = {"Authorization": f"Bearer {token}"}
    tn = ST["tn"]
    tn_hdrs = {"Authentication":f"bearer {tn['token']}","Content-Type":"application/json"}
    agrupar = b.get("agrupar", False)
    results = []

    async with httpx.AsyncClient(timeout=20) as c:

        if agrupar:
            # Bajar todos los items primero
            all_items = []
            for iid in item_ids:
                try:
                    r = await c.get(f"{ML_API}/items/{iid}", headers=ml_hdrs)
                    item = r.json()
                    dr = await c.get(f"{ML_API}/items/{iid}/description", headers=ml_hdrs)
                    item["_desc"] = dr.json().get("plain_text", item.get("title",""))
                    if "error" not in item:
                        all_items.append(item)
                    await asyncio.sleep(0.3)
                except Exception:
                    pass

            # Agrupar por MODEL
            grupos = {}
            for item in all_items:
                model_attr = next((a for a in (item.get("attributes") or []) if a.get("id") == "MODEL"), None)
                key = model_attr.get("value_name", item["id"]) if model_attr else item["id"]
                if key not in grupos:
                    grupos[key] = []
                grupos[key].append(item)

            for model_key, items_grupo in grupos.items():
                try:
                    base = items_grupo[0]
                    # Título base: cortar después del número de modelo
                    _t = base.get("title","")
                    _m = next((a.get("value_name","") for a in (base.get("attributes") or []) if a.get("id")=="MODEL"), "")
                    if _m and _m in _t:
                        title = _t[:_t.index(_m)+len(_m)].strip()
                    elif " - " in _t:
                        title = _t.rsplit(" - ", 1)[0].strip()
                    else:
                        title = _t
                    desc = base.get("_desc", title)

                    # Armar variantes TN: una por item, con COLOR y SIZE como values
                    variants = []
                    for item in items_grupo:
                        attrs = {a["id"]: a for a in (item.get("attributes") or [])}
                        color = attrs.get("COLOR",{}).get("value_name","")
                        size = attrs.get("SIZE",{}).get("value_name") or attrs.get("SIZE",{}).get("value_id","")
                        values = []
                        if color: values.append({"es": color})
                        if size: values.append({"es": size})
                        v = {
                            "price": str(item.get("price", base.get("price",0))),
                            "stock_management": True,
                            "stock": item.get("available_quantity", 0),
                        }
                        if values: v["values"] = values
                        variants.append(v)

                    # Imágenes de todos los items del grupo
                    pics = []
                    seen = set()
                    for item in items_grupo:
                        for p in (item.get("pictures") or [])[:2]:
                            url = p.get("url","")
                            if url and url not in seen:
                                pics.append({"src": url})
                                seen.add(url)
                        if len(pics) >= 10: break

                    payload = {
                        "name": {"es": title},
                        "description": {"es": desc},
                        "published": True,
                        "variants": variants,
                        "images": pics[:10],
                    }
                    pr = await c.post(f"https://api.tiendanube.com/v1/{tn['store_id']}/products",
                                      headers=tn_hdrs, json=payload)
                    ok = pr.status_code in (200,201)
                    msg = f"Publicado con {len(variants)} variantes" if ok else pr.json().get("description","Error")
                    results.append({"id": base["id"], "title": title, "ok": ok, "msg": msg})
                    ST["log"].append({"ts":int(time.time()),"action":"publish_tn_group","product":title,"status":"ok" if ok else "error"})
                    await asyncio.sleep(0.5)
                except Exception as e:
                    results.append({"id": model_key, "title": model_key, "ok": False, "msg": str(e)})

        else:
            # Publicar uno por uno (comportamiento original)
            for iid in item_ids:
                try:
                    r = await c.get(f"{ML_API}/items/{iid}", headers=ml_hdrs)
                    item = r.json()
                    dr = await c.get(f"{ML_API}/items/{iid}/description", headers=ml_hdrs)
                    desc = dr.json().get("plain_text", item.get("title",""))
                    variations = item.get("variations",[])
                    if variations:
                        variants = [{"price":str(v.get("price",item.get("price",0))),
                                     "stock_management":True,"stock":v.get("available_quantity",0),
                                     "values":[{"es":a["value_name"]} for a in v.get("attribute_combinations",[])]}
                                    for v in variations]
                    else:
                        variants = [{"price":str(item.get("price",0)),"stock_management":True,
                                     "stock":item.get("available_quantity",0)}]
                    payload = {"name":{"es":item["title"]},"description":{"es":desc},
                               "published":True,"variants":variants,
                               "images":[{"src":p["url"]} for p in (item.get("pictures") or [])[:5]]}
                    pr = await c.post(f"https://api.tiendanube.com/v1/{tn['store_id']}/products",
                                      headers=tn_hdrs, json=payload)
                    ok = pr.status_code in (200,201)
                    results.append({"id":iid,"title":item.get("title",""),"ok":ok,
                                     "msg":"Publicado" if ok else pr.json().get("description","Error")})
                    ST["log"].append({"ts":int(time.time()),"action":"publish","product":item.get("title",""),
                                      "status":"ok" if ok else "error"})
                    await asyncio.sleep(0.3)
                except Exception as e:
                    results.append({"id":iid,"ok":False,"msg":str(e)})
    save_state()
    return {"results": results}

@app.post("/api/duplicate")
async def duplicate(req: Request, _=Depends(auth)):
    b = await req.json()
    from_idx = b.get("from_account", 0)
    to_idx = b.get("to_account", 1)
    status = b.get("status", "active")
    auto_link = b.get("auto_link", False)
    agrupar = b.get("agrupar", False)
    explotar = b.get("explotar", False)
    try:
        from_t = await fresh_token(from_idx)
        to_t = await fresh_token(to_idx)
    except Exception as e:
        raise HTTPException(400, f"Error de token: {str(e)}")

    # Cache de guías de talles ya copiadas en esta sesión: {chart_id_origen: chart_id_destino}
    size_chart_map = {}

    async def copy_size_chart(c, chart_id: str):
        """Copia una guía de talles de cuenta origen a destino. Devuelve el nuevo ID."""
        if chart_id in size_chart_map:
            return size_chart_map[chart_id]
        try:
            # Obtener la guía original
            r = await c.get(f"{ML_API}/size_charts/{chart_id}",
                           headers={"Authorization": f"Bearer {from_t}"})
            if r.status_code != 200:
                return None
            chart = r.json()

            # Obtener el user_id de la cuenta destino
            me_r = await c.get(f"{ML_API}/users/me",
                               headers={"Authorization": f"Bearer {to_t}"})
            to_uid = me_r.json().get("id")

            # Armar payload para crear la guía en destino
            payload = {
                "site_id": chart.get("site_id", "MLA"),
                "name": chart.get("name", "Guía de talles"),
                "category_id": chart.get("category_id"),
                "domain_id": chart.get("domain_id"),
                "attributes": chart.get("attributes", []),
                "rows": chart.get("rows", []),
            }
            # Remover claves None
            payload = {k: v for k, v in payload.items() if v is not None}

            r2 = await c.post(f"{ML_API}/size_charts",
                             headers={"Authorization": f"Bearer {to_t}"},
                             json=payload)
            if r2.status_code in (200, 201):
                new_chart_id = r2.json().get("id")
                size_chart_map[chart_id] = new_chart_id
                return new_chart_id
            else:
                # Si falla la creación, intentar reutilizar la misma (si es pública/compartida)
                size_chart_map[chart_id] = chart_id
                return chart_id
        except Exception:
            return chart_id  # fallback: usar el mismo ID

    # Detectar si cuenta destino es user_product_seller y preparar carga de guías
    dest_is_up = False
    dest_charts_cache = {}  # chart_id -> {chart_id, rows: {size_name: row_id}}
    # Cargar overrides de guías seleccionadas por el usuario
    chart_override = {}
    try:
        r_redis = get_redis()
        if r_redis:
            raw = r_redis.get("mltn:chart_override")
            if raw:
                chart_override = json.loads(raw)
    except Exception:
        pass
    # Hardcode conocidos: guía origen -> guía destino por cuenta
    KNOWN_CHARTS = {
        # LENCERIA pijamas (4788364) -> SHAMPOOSHIR pijamas (5127137)
        "4788364": {"chart_id": "5127137", "rows": {"XL-2XL": "5127137:1", "3XL-4XL": "5127137:2"}},
        # También mapear 4666038 por si acaso
        "4666038": {"chart_id": "5127137", "rows": {"XL-2XL": "5127137:1", "3XL-4XL": "5127137:2"}},
    }

    async def get_dest_user_info():
        nonlocal dest_is_up
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(f"{ML_API}/users/me", headers={"Authorization": f"Bearer {to_t}"})
            try:
                data = r.json() if r.content else {}
            except Exception:
                data = {}
            tags = data.get("tags", [])
            dest_is_up = "user_product_seller" in tags

    async def load_dest_chart(orig_chart_id: str, domain_id: str = "", brand: str = ""):
        """Buscar guía de talles equivalente en cuenta destino"""
        cache_key = f"{orig_chart_id}"
        if cache_key in dest_charts_cache:
            return dest_charts_cache[cache_key]
        # Verificar override del usuario (por ID específico o "manual" para cualquiera)
        override_key = orig_chart_id if orig_chart_id in chart_override else ("manual" if "manual" in chart_override else None)
        if override_key:
            orig_chart_id = override_key  # reusar lógica abajo
        if orig_chart_id in chart_override:
            override_id = chart_override[orig_chart_id]
            try:
                async with httpx.AsyncClient(timeout=10) as c:
                    r = await c.get(f"{ML_API}/catalog/charts/{override_id}",
                                   headers={"Authorization": f"Bearer {to_t}"})
                    if r.status_code == 200:
                        row_map = {}
                        for row in (r.json().get("rows") or []):
                            rid = row.get("id","")
                            sv = next((v.get("name","") for a in row.get("attributes",[])
                                       if a.get("id")=="SIZE" for v in a.get("values",[])), "")
                            if sv and rid:
                                row_map[sv] = rid
                        result = {"chart_id": override_id, "rows": row_map}
                        dest_charts_cache[cache_key] = result
                        return result
            except Exception:
                pass
        # Usar mapeo conocido si existe
        if orig_chart_id in KNOWN_CHARTS:
            result = KNOWN_CHARTS[orig_chart_id]
            dest_charts_cache[cache_key] = result
            return result
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                # Para UP siempre buscar en las guías del vendedor destino
                # Para no-UP: intentar leer la guía origen directamente
                if not dest_is_up:
                    r = await c.get(f"{ML_API}/catalog/charts/{orig_chart_id}",
                                   headers={"Authorization": f"Bearer {to_t}"})
                    if r.status_code == 200:
                        chart = r.json()
                        # Solo usar si es del vendedor destino
                        if str(chart.get("seller_id","")) == str(to_uid if False else ""):
                            pass  # skip, we don't have to_uid yet
                        row_map = {}
                        for row in (chart.get("rows") or []):
                            rid = row.get("id","")
                            size_val = next((v.get("name","") for a in row.get("attributes",[])
                                            if a.get("id")=="SIZE" for v in a.get("values",[])), "")
                            if size_val and rid:
                                row_map[size_val] = rid
                        result = {"chart_id": orig_chart_id, "rows": row_map}
                        dest_charts_cache[cache_key] = result
                        return result

                # Buscar guías del vendedor destino por dominio
                me_r = await c.get(f"{ML_API}/users/me", headers={"Authorization": f"Bearer {to_t}"})
                to_uid = me_r.json().get("id","")

                # Buscar guías de la cuenta destino — primero con brand, luego sin brand
                charts = []
                for search_payload in [
                    {"site_id":"MLA","seller_id": to_uid, "domain_id": domain_id or "BRAS",
                     "attributes":[{"id":"GENDER","values":[{"name":"Mujer"}]},{"id":"BRAND","values":[{"name": brand or ""}]}]},
                    {"site_id":"MLA","seller_id": to_uid, "domain_id": domain_id or "BRAS",
                     "attributes":[{"id":"GENDER","values":[{"name":"Mujer"}]}]},
                    {"site_id":"MLA","seller_id": to_uid, "domain_id": domain_id or "BRAS"},
                ]:
                    search_r = await c.post(f"{ML_API}/catalog/charts/search",
                        headers={"Authorization": f"Bearer {to_t}", "Content-Type": "application/json"},
                        json=search_payload)
                    if search_r.status_code == 200:
                        charts = search_r.json().get("charts", [])
                        if charts:
                            break

                # Elegir la guía que tenga el talle que necesitamos
                best = None
                # Primero buscar la guía que ya tenga el size_val en sus rows
                for ch in charts:
                    for row in (ch.get("rows") or []):
                        sv = next((v.get("name","") for a in row.get("attributes",[])
                                   if a.get("id")=="SIZE" for v in a.get("values",[])), "")
                        if sv == size_val:
                            best = ch
                            break
                    if best:
                        break
                # Si ninguna tiene el talle, tomar la que coincida por brand
                if not best:
                    for ch in charts:
                        ch_name = ch.get("names",{}).get("MLA","").upper()
                        if brand and brand.upper() in ch_name:
                            best = ch
                            break
                if not best and charts:
                    best = charts[0]

                if best:
                    # Cargar los rows de la mejor guía
                    r2 = await c.get(f"{ML_API}/catalog/charts/{best['id']}",
                                    headers={"Authorization": f"Bearer {to_t}"})
                    if r2.status_code == 200:
                        chart = r2.json()
                        row_map = {}
                        for row in (chart.get("rows") or []):
                            rid = row.get("id","")
                            size_val = next((v.get("name","") for a in row.get("attributes",[])
                                            if a.get("id")=="SIZE" for v in a.get("values",[])), "")
                            if size_val and rid:
                                row_map[size_val] = rid
                        result = {"chart_id": str(best["id"]), "rows": row_map}
                        dest_charts_cache[cache_key] = result
                        return result
        except Exception:
            pass
        return None

    async def copy_chart_to_dest(orig_chart_id: str, domain_id: str = ""):
        """Copiar guía de talles de cuenta origen a cuenta destino"""
        cache_key = f"copy_{orig_chart_id}"
        if cache_key in dest_charts_cache:
            return dest_charts_cache[cache_key]
        try:
            async with httpx.AsyncClient(timeout=20) as c:
                # Leer guía original con token origen
                r = await c.get(f"{ML_API}/catalog/charts/{orig_chart_id}",
                               headers={"Authorization": f"Bearer {from_t}"})
                if r.status_code != 200:
                    return None
                orig = r.json()

                # Armar payload para crear la guía en destino
                new_chart = {
                    "names": orig.get("names", {"MLA": "Guía de talles"}),
                    "domain_id": orig.get("domain_id") or domain_id or "BRAS",
                    "site_id": orig.get("site_id", "MLA"),
                    "main_attribute": {"attributes": [{"site_id": "MLA", "id": orig.get("main_attribute_id", "SIZE")}]},
                    "attributes": orig.get("attributes", []),
                    "rows": []
                }
                if orig.get("measure_type"):
                    new_chart["measure_type"] = orig["measure_type"]

                # Copiar rows — limpiar IDs
                for row in (orig.get("rows") or []):
                    new_row = {"attributes": []}
                    for a in row.get("attributes", []):
                        new_row["attributes"].append({
                            "id": a["id"],
                            "values": a.get("values", [])
                        })
                    new_chart["rows"].append(new_row)

                r2 = await c.post(f"{ML_API}/catalog/charts",
                                 headers={"Authorization": f"Bearer {to_t}", "Content-Type": "application/json"},
                                 json=new_chart)

                if r2.status_code in (200, 201):
                    new_chart_data = r2.json()
                    new_id = str(new_chart_data.get("id",""))
                    # Cargar los rows del nuevo chart
                    row_map = {}
                    for row in (new_chart_data.get("rows") or []):
                        rid = row.get("id","")
                        size_val2 = next((v.get("name","") for a in row.get("attributes",[])
                                         if a.get("id")=="SIZE" for v in a.get("values",[])), "")
                        if size_val2 and rid:
                            row_map[size_val2] = rid
                    result = {"chart_id": new_id, "rows": row_map}
                    dest_charts_cache[cache_key] = result
                    dest_charts_cache[orig_chart_id] = result  # también cachear por ID original
                    return result
        except Exception:
            pass
        return None

    await get_dest_user_info()

    results = []
    item_ids = b.get("item_ids", [])

    # Si explotar=True, expandir variantes como productos separados
    if explotar:
        new_item_ids = []
        for iid in item_ids:
            try:
                async with httpx.AsyncClient(timeout=15) as c:
                    r = await c.get(f"{ML_API}/items/{iid}", headers={"Authorization": f"Bearer {from_t}"})
                    if r.status_code == 200:
                        item = r.json()
                        variations = item.get("variations", [])
                        if variations:
                            # Crear un item por cada variante
                            for v in variations:
                                attrs = {a["name"]: a["value_name"] for a in v.get("attribute_combinations", [])}
                                # Buscar talle con cualquier key posible
                                talle = (attrs.get("Talle") or attrs.get("Tamaño") or 
                                        attrs.get("Size") or attrs.get("Talla") or
                                        next((v for k,v in attrs.items() if "tall" in k.lower() or "size" in k.lower() or "tamaño" in k.lower()), ""))
                                color = (attrs.get("Color") or 
                                        next((v for k,v in attrs.items() if "color" in k.lower()), ""))
                                print(f"Variante attrs: {attrs}, talle={talle}, color={color}")
                                suffix = " - ".join(filter(None, [talle, color]))
                                new_title = f"{item['title']} - {suffix}" if suffix else item["title"]
                                price = v.get("price") or item.get("price", 0)
                                stock = v.get("available_quantity", item.get("available_quantity", 0))
                                # Construir atributos — tomar del item original
                                item_attrs = [a for a in (item.get("attributes") or []) 
                                              if a.get("id") not in ("SIZE_GRID_ID", "SIZE", "COLOR")]
                                # Agregar SIZE y COLOR de esta variante
                                if talle:
                                    item_attrs.append({"id": "SIZE", "value_name": talle})
                                if color:
                                    item_attrs.append({"id": "COLOR", "value_name": color})
                                # Agregar family_name requerido por ML
                                item_attrs.append({"id": "FAMILY_NAME", "value_name": item.get("title", "")[:60]})
                                # Agregar SIZE_GRID_ID con override o el original
                                orig_chart_id = str(next((a.get("value_name","") for a in (item.get("attributes") or []) if a.get("id")=="SIZE_GRID_ID"), "") or "")
                                dest_chart_id = chart_override.get(orig_chart_id) or chart_override.get("manual", "")
                                if dest_chart_id:
                                    item_attrs.append({"id": "SIZE_GRID_ID", "value_name": str(dest_chart_id)})
                                elif orig_chart_id:
                                    item_attrs.append({"id": "SIZE_GRID_ID", "value_name": orig_chart_id})
                                payload = {
                                    "title": new_title,
                                    "category_id": item.get("category_id"),
                                    "price": price,
                                    "currency_id": item.get("currency_id", "ARS"),
                                    "available_quantity": stock,
                                    "buying_mode": "buy_it_now",
                                    "listing_type_id": item.get("listing_type_id", "gold_special"),
                                    "condition": item.get("condition", "new"),
                                    "pictures": [{"source": p["url"]} for p in (item.get("pictures") or [])[:12]],
                                    "attributes": item_attrs,
                                    "family_name": item.get("title","")
                                }
                                async with httpx.AsyncClient(timeout=30) as c2:
                                    r2 = await c2.post(f"{ML_API}/items",
                                        headers={"Authorization": f"Bearer {to_t}"},
                                        json=payload)
                                ok = r2.status_code in (200, 201)
                                if not ok:
                                    err_body = r2.json()
                                    print(f"ML error {r2.status_code}: {json.dumps(err_body)[:500]}")
                                results.append({"id": iid, "title": new_title, "ok": ok,
                                    "msg": "Publicado" if ok else r2.json().get("cause",[{}])[0].get("message", r2.json().get("message","Error"))})
                        else:
                            new_item_ids.append(iid)
                    else:
                        new_item_ids.append(iid)
            except Exception as e:
                results.append({"id": iid, "title": iid, "ok": False, "msg": str(e)})
        # Los items sin variantes se procesan normal
        item_ids = new_item_ids
        if not item_ids:
            return {"results": results}

    # Si agrupar=True, obtener todos los items primero y agrupar por MODEL
    if agrupar:
        async with httpx.AsyncClient(timeout=30) as c:
            # Bajar todos los items
            all_items = []
            for iid in item_ids:
                try:
                    r = await c.get(f"{ML_API}/items/{iid}", headers={"Authorization": f"Bearer {from_t}"})
                    item = r.json()
                    if "error" not in item:
                        all_items.append(item)
                    await asyncio.sleep(0.5)
                except Exception:
                    pass

            # Agrupar por MODEL
            grupos = {}
            for item in all_items:
                model_attr = next((a for a in (item.get("attributes") or []) if a.get("id") == "MODEL"), None)
                key = model_attr.get("value_name", item["id"]) if model_attr else item["id"]
                if key not in grupos:
                    grupos[key] = []
                grupos[key].append(item)

            # Procesar cada grupo
            for model_key, items_grupo in grupos.items():
                try:
                    base_item = items_grupo[0]

                    # Armar variaciones combinando COLOR + SIZE de cada item
                    variations = []
                    for item in items_grupo:
                        attrs = {a["id"]: a for a in (item.get("attributes") or [])}
                        color_id = attrs.get("COLOR", {}).get("value_id")
                        color_name = attrs.get("COLOR", {}).get("value_name")
                        size_id = attrs.get("SIZE", {}).get("value_id")
                        size_name = attrs.get("SIZE", {}).get("value_name")
                        combinations = []
                        if color_id or color_name:
                            c_attr = {"id": "COLOR"}
                            if color_id: c_attr["value_id"] = color_id
                            else: c_attr["value_name"] = color_name
                            combinations.append(c_attr)
                        if size_id or size_name:
                            s_attr = {"id": "SIZE"}
                            if size_id: s_attr["value_id"] = size_id
                            else: s_attr["value_name"] = size_name
                            combinations.append(s_attr)
                        v = {
                            "price": item.get("price", base_item.get("price", 0)),
                            "available_quantity": item.get("available_quantity", 0),
                            "attribute_combinations": combinations,
                            "picture_ids": [p["id"] for p in (item.get("pictures") or [])[:3] if p.get("id")],
                        }
                        variations.append(v)

                    # Limpiar atributos del item base
                    EXCLUDED_ATTRS = {"SELLER_SKU","ITEM_CONDITION","ALPHANUMERIC_MODEL","GTIN",
                                      "PACKAGE_DATA_SOURCE","RELEASE_YEAR","SYI_PYMES_ID",
                                      "FILTRABLE_SIZE","SIZE_GRID_ROW_ID","SIZE_GRID_ID","COLOR","SIZE"}
                    brand_val = next((a.get("value_name","") for a in (base_item.get("attributes") or []) if a.get("id")=="BRAND"), "")
                    model_val2 = next((a.get("value_name","") for a in (base_item.get("attributes") or []) if a.get("id")=="MODEL"), "")
                    attrs_clean = []
                    for a in (base_item.get("attributes") or []):
                        aid = a.get("id","")
                        if aid in EXCLUDED_ATTRS: continue
                        if aid in ("BRAND","MODEL"):
                            vn = a.get("value_name")
                            if vn: attrs_clean.append({"id":aid,"value_name":vn})
                            continue
                        if a.get("value_id"):
                            attrs_clean.append({"id": aid, "value_id": a["value_id"]})
                        elif a.get("value_name"):
                            attrs_clean.append({"id": aid, "value_name": a["value_name"]})
                    family2 = f"{brand_val} {model_val2}".strip() or base_item.get("title","")[:60]
                    attrs_clean.append({"id": "family_name", "value_name": family2})

                    # Título base: cortar después del número de modelo
                    _t = base_item.get("title", "")
                    if model_val2 and model_val2 in _t:
                        title = _t[:_t.index(model_val2)+len(model_val2)].strip()
                    elif " - " in _t:
                        title = _t.rsplit(" - ", 1)[0].strip()
                    else:
                        title = _t

                    payload = {
                        "title": title,
                        "category_id": base_item.get("category_id", ""),
                        "price": base_item.get("price", 0),
                        "currency_id": base_item.get("currency_id", "ARS"),
                        "available_quantity": 0,
                        "listing_type_id": base_item.get("listing_type_id", "gold_special"),
                        "condition": base_item.get("condition", "new"),
                        "pictures": [{"source": p["url"]} for p in (base_item.get("pictures") or [])[:12]],
                        "attributes": attrs_clean,
                        "variations": variations,
                    }
                    if base_item.get("sale_terms"):
                        payload["sale_terms"] = base_item["sale_terms"]

                    # Intentar con retry 429
                    r2 = None
                    for attempt in range(3):
                        r2 = await c.post(f"{ML_API}/items", headers={"Authorization": f"Bearer {to_t}"}, json=payload)
                        if r2.status_code == 429:
                            await asyncio.sleep(30 * (attempt + 1))
                            continue
                        break

                    ok = r2.status_code in (200, 201)
                    new_id = None
                    if ok:
                        new_id = r2.json().get("id")
                        msg = f"Agrupado OK ({len(items_grupo)} variantes)"
                        if status == "paused" and new_id:
                            await c.put(f"{ML_API}/items/{new_id}",
                                headers={"Authorization": f"Bearer {to_t}"},
                                json={"status": "paused"})
                    elif r2.status_code == 429:
                        msg = "Rate limit ML (429)"
                    else:
                        try:
                            err = r2.json()
                            causes = err.get("cause", [])
                            msg = ", ".join([cx.get("code","") for cx in causes[:3]]) if causes else err.get("message", f"Error {r2.status_code}")
                        except Exception:
                            msg = f"Error {r2.status_code}"

                    results.append({"id": base_item["id"], "title": title, "ok": ok, "msg": msg, "new_id": new_id, "variantes": len(items_grupo)})
                    ST["log"].append({"ts": int(time.time()), "action": "duplicate_group", "product": title, "status": "ok" if ok else "error"})
                    await asyncio.sleep(3)

                except Exception as e:
                    results.append({"id": model_key, "title": model_key, "ok": False, "msg": str(e)})

        save_state()
        return {"results": results}

    # Modo normal: duplicar uno por uno
    async with httpx.AsyncClient(timeout=30) as c:
        for iid in item_ids:
            try:
                r = await c.get(f"{ML_API}/items/{iid}", headers={"Authorization": f"Bearer {from_t}"})
                item = r.json()
                if "error" in item:
                    results.append({"id": iid, "title": iid, "ok": False, "msg": item.get("message", "Error ML")})
                    continue

                # Limpiar variaciones
                variations_clean = []
                for v in (item.get("variations") or []):
                    vc = {
                        "attribute_combinations": v.get("attribute_combinations", []),
                        "price": v.get("price", item.get("price", 0)),
                        "available_quantity": v.get("available_quantity", 0),
                    }
                    if v.get("picture_ids"):
                        vc["picture_ids"] = v["picture_ids"]
                    variations_clean.append(vc)

                # Atributos a excluir
                EXCLUDED_ATTRS = {
                    "SELLER_SKU","ITEM_CONDITION","ALPHANUMERIC_MODEL","GTIN",
                    "PACKAGE_DATA_SOURCE","RELEASE_YEAR","SYI_PYMES_ID",
                    "FILTRABLE_SIZE","SIZE_GRID_ROW_ID","SIZE_GRID_ID"
                }
                # Extraer BRAND y MODEL primero
                brand_val = next((a.get("value_name","") for a in (item.get("attributes") or []) if a.get("id")=="BRAND"), "")
                model_val = next((a.get("value_name","") for a in (item.get("attributes") or []) if a.get("id")=="MODEL"), "")
                size_val = next((a.get("value_name") or str(a.get("value_id","")) for a in (item.get("attributes") or []) if a.get("id")=="SIZE"), "")
                orig_chart_id = next((a.get("value_name") or a.get("value_id","") for a in (item.get("attributes") or []) if a.get("id")=="SIZE_GRID_ID"), None)
                orig_row_id = next((a.get("value_name","") for a in (item.get("attributes") or []) if a.get("id")=="SIZE_GRID_ROW_ID"), None)

                attrs_clean = []
                for a in (item.get("attributes") or []):
                    aid = a.get("id","")
                    if aid in EXCLUDED_ATTRS: continue
                    if aid in ("BRAND","MODEL"):
                        vn = a.get("value_name")
                        if vn: attrs_clean.append({"id":aid,"value_name":vn})
                        continue
                    if aid == "SIZE":
                        if dest_is_up:
                            # UP: SIZE como value_name
                            if size_val: attrs_clean.append({"id":"SIZE","value_name":size_val})
                        else:
                            if a.get("value_id"): attrs_clean.append({"id":"SIZE","value_id":a["value_id"]})
                            elif a.get("value_name"): attrs_clean.append({"id":"SIZE","value_name":a["value_name"]})
                        continue
                    if dest_is_up:
                        # Para UP: siempre value_name
                        vn = a.get("value_name")
                        if vn:
                            attrs_clean.append({"id": aid, "value_name": vn})
                    else:
                        if a.get("value_id"):
                            attrs_clean.append({"id": aid, "value_id": a["value_id"]})
                        elif a.get("value_name"):
                            attrs_clean.append({"id": aid, "value_name": a["value_name"]})

                # Agregar SIZE_GRID_ID y SIZE_GRID_ROW_ID
                if orig_chart_id:
                    # Para UP: buscar guía en cuenta destino por su ID
                    if dest_is_up:
                        # Obtener domain_id de la categoría
                        cat_domain = ""
                        try:
                            async with httpx.AsyncClient(timeout=10) as cc:
                                dr = await cc.get(f"{ML_API}/categories/{item.get('category_id','')}", 
                                                  headers={"Authorization": f"Bearer {from_t}"})
                                cat_domain = dr.json().get("domain_id","")
                        except Exception:
                            pass
                        dest_chart = await load_dest_chart(str(orig_chart_id), cat_domain, brand_val)
                        if not dest_chart:
                            # Intentar copiar la guía automáticamente
                            dest_chart = await copy_chart_to_dest(str(orig_chart_id), cat_domain)
                        if dest_chart:
                            attrs_clean.append({"id":"SIZE_GRID_ID","value_name":str(dest_chart["chart_id"])})
                            row_id = dest_chart["rows"].get(size_val)
                            if not row_id:
                                # Agregar el talle faltante via POST /catalog/charts/{id}/rows
                                try:
                                    async with httpx.AsyncClient(timeout=20) as cc:
                                        # Leer guía original para copiar el row con todos sus atributos
                                        orig_chart_r = await cc.get(
                                            f"{ML_API}/catalog/charts/{orig_chart_id}",
                                            headers={"Authorization": f"Bearer {from_t}"}
                                        )
                                        orig_row_data = None
                                        if orig_chart_r.status_code == 200:
                                            for r in (orig_chart_r.json().get("rows") or []):
                                                sv = next((v.get("name","") for a in r.get("attributes",[])
                                                           if a.get("id")=="SIZE" for v in a.get("values",[])), "")
                                                if sv == size_val:
                                                    orig_row_data = r
                                                    break
                                        # Armar payload del nuevo row limpiando IDs
                                        if orig_row_data:
                                            new_row_attrs = []
                                            for a in orig_row_data.get("attributes", []):
                                                new_row_attrs.append({"id": a["id"], "values": a.get("values", [])})
                                        else:
                                            new_row_attrs = [{"id": "SIZE", "values": [{"name": size_val}]}]
                                        add_r = await cc.post(
                                            f"{ML_API}/catalog/charts/{dest_chart['chart_id']}/rows",
                                            headers={"Authorization": f"Bearer {to_t}", "Content-Type": "application/json"},
                                            json={"attributes": new_row_attrs}
                                        )
                                        if add_r.status_code in (200, 201):
                                            added = add_r.json()
                                            row_id = added.get("id", "")
                                            if row_id:
                                                dest_chart["rows"][size_val] = row_id
                                except Exception:
                                    pass
                            if row_id:
                                attrs_clean.append({"id":"SIZE_GRID_ROW_ID","value_name":row_id})
                            else:
                                results.append({"id": iid, "title": item.get("title", iid), "ok": False,
                                    "msg": f"⚠️ El talle '{size_val}' no existe en la guía de talles de la cuenta destino.",
                                    "error_type": "missing_size",
                                    "missing_size": size_val,
                                    "chart_id": dest_chart["chart_id"],
                                    "ml_talles_url": "https://www.mercadolibre.com.ar/moda/talles/"})
                                continue
                        else:
                            results.append({"id": iid, "title": item.get("title", iid), "ok": False,
                                "msg": f"⚠️ No hay guía de talles para '{brand_val}' en la cuenta destino. SIZE_GRID_ID origen: {orig_chart_id}",
                                "error_type": "missing_chart",
                                "domain_id": cat_domain,
                                "brand": brand_val,
                                "orig_chart_id": str(orig_chart_id),
                                "ml_talles_url": "https://www.mercadolibre.com.ar/moda/talles/"})
                            continue
                    else:
                        attrs_clean.append({"id":"SIZE_GRID_ID","value_name":str(orig_chart_id)})
                        if orig_row_id:
                            attrs_clean.append({"id":"SIZE_GRID_ROW_ID","value_name":orig_row_id})

                # family_name
                family = f"{brand_val} {model_val}".strip() or item.get("title","")[:60]

                # Título base: cortar después del modelo
                raw_title = item.get("title","")
                if model_val and model_val in raw_title:
                    base_title = raw_title[:raw_title.index(model_val)+len(model_val)].strip()
                elif " - " in raw_title:
                    base_title = raw_title.rsplit(" - ", 1)[0].strip()
                else:
                    base_title = raw_title.strip()

                if dest_is_up:
                    payload = {
                        "family_name": base_title[:60],
                        "category_id": item.get("category_id", ""),
                        "price": item.get("price", 0),
                        "currency_id": item.get("currency_id", "ARS"),
                        "available_quantity": item.get("available_quantity", 0),
                        "listing_type_id": item.get("listing_type_id", "gold_special"),
                        "condition": item.get("condition", "new"),
                        "pictures": [{"source": p["url"].replace("http://","https://")} for p in (item.get("pictures") or [])[:12]],
                        "attributes": attrs_clean,
                    }
                else:
                    payload = {
                        "title": base_title[:60],
                        "category_id": item.get("category_id", ""),
                        "price": item.get("price", 0),
                        "currency_id": item.get("currency_id", "ARS"),
                        "available_quantity": item.get("available_quantity", 0) if not variations_clean else 0,
                        "listing_type_id": item.get("listing_type_id", "gold_special"),
                        "condition": item.get("condition", "new"),
                        "pictures": [{"source": p["url"].replace("http://","https://")} for p in (item.get("pictures") or [])[:12]],
                        "attributes": attrs_clean,
                    }
                    if variations_clean:
                        payload["variations"] = variations_clean
                    if item.get("sale_terms"):
                        payload["sale_terms"] = item["sale_terms"]

                # Intentar con retry en 429
                r2 = None
                for attempt in range(3):
                    r2 = await c.post(f"{ML_API}/items", headers={"Authorization": f"Bearer {to_t}"}, json=payload)
                    if r2.status_code == 429:
                        wait = 30 * (attempt + 1)
                        await asyncio.sleep(wait)
                        continue
                    break

                ok = r2.status_code in (200, 201)

                new_id = None
                if ok:
                    new_id = r2.json().get("id")
                    msg = "Duplicado OK"
                    if status == "paused" and new_id:
                        await c.put(f"{ML_API}/items/{new_id}",
                            headers={"Authorization": f"Bearer {to_t}"},
                            json={"status": "paused"})
                    if auto_link and new_id:
                        link = {"ml_item_id": iid, "ml_acc_idx": from_idx,
                                "tn_product_id": new_id, "tn_acc_idx": to_idx,
                                "auto_linked": True}
                        if "links" not in ST: ST["links"] = []
                        ST["links"].append(link)
                elif r2.status_code == 429:
                    msg = "Rate limit ML (429) — esperá unos minutos y volvé a intentar"
                else:
                    try:
                        err = r2.json()
                        causes = err.get("cause", [])
                        # Solo mostrar errores reales, ignorar warnings
                        real_errors = [c2 for c2 in causes if c2.get("type") == "error"]
                        msg = ", ".join([c2.get("message", c2.get("code","")) for c2 in real_errors[:3]]) if real_errors else err.get("message", f"Error {r2.status_code}")
                    except Exception:
                        msg = f"Error {r2.status_code}"

                results.append({"id": iid, "title": item.get("title", iid), "ok": ok, "msg": msg, "new_id": new_id})
                ST["log"].append({"ts": int(time.time()), "action": "duplicate", "product": item.get("title", ""), "status": "ok" if ok else "error"})
                await asyncio.sleep(3)  # 3 segundos entre cada item para no disparar 429
            except Exception as e:
                results.append({"id": iid, "title": iid, "ok": False, "msg": str(e)})
    save_state()
    return {"results": results}

@app.get("/diag/prod_attrs/{i}")
async def diag_prod_attrs(i: int, q: str = ""):
    """Ver atributos de productos cacheados, buscar por título"""
    try:
        acc = ST["accounts"][i]
        uid = acc.get("uid","")
        prods = get_cached_products(uid)
        if not prods:
            return {"error": "no products cached"}
        if q:
            prods = [p for p in prods if q.lower() in p.get("title","").lower()]
        if not prods:
            return {"error": "no matching products"}
        p = prods[0]
        attrs = p.get("attributes", [])
        return {"title": p.get("title",""), "attr_count": len(attrs), "all_attrs": attrs}
    except Exception as e:
        return {"error": str(e)}

@app.get("/diag/item/{item_id}")
async def diag_item(item_id: str):
    if not ST["accounts"]:
        return {"error": "no accounts"}
    try:
        from_t = await fresh_token(0)
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(f"{ML_API}/items/{item_id}",
                           headers={"Authorization": f"Bearer {from_t}"})
            raw = r.text[:3000]
            try:
                item = r.json()
            except Exception:
                return {"http_status": r.status_code, "raw_response": raw}

            # Obtener guía de talles si existe
            size_grid = None
            size_grid_error = None
            size_attr = next((a for a in item.get("attributes",[]) if a.get("id")=="SIZE_GRID_ID"), None)
            if size_attr:
                chart_id = size_attr.get("value_name") or size_attr.get("value_id")
                if chart_id:
                    sg = await c.get(f"{ML_API}/size_charts/{chart_id}",
                                    headers={"Authorization": f"Bearer {from_t}"})
                    try:
                        size_grid = sg.json()
                        size_grid_error = None if sg.status_code == 200 else f"HTTP {sg.status_code}"
                    except Exception:
                        size_grid_error = sg.text[:200]

            return {
                "http_status": r.status_code,
                "title": item.get("title"),
                "category_id": item.get("category_id"),
                "variations_count": len(item.get("variations", [])),
                "size_grid_attr": size_attr,
                "size_grid_response": size_grid,
                "size_grid_error": size_grid_error,
                "ml_error": item.get("error"),
            }
    except Exception as e:
        return {"exception": str(e)}

@app.get("/api/ml/{i}/charts")
async def list_charts(i: int, _=Depends(auth)):
    """Listar guías de talles de una cuenta ML"""
    try:
        t = await fresh_token(i)
        async with httpx.AsyncClient(timeout=15) as c:
            me_r = await c.get(f"{ML_API}/users/me", headers={"Authorization": f"Bearer {t}"})
            uid = str(me_r.json().get("id",""))
            r = await c.post(f"{ML_API}/catalog/charts/search",
                headers={"Authorization": f"Bearer {t}", "Content-Type": "application/json"},
                json={"site_id": "MLA", "seller_id": int(uid) if uid.isdigit() else uid})
            if r.status_code == 200:
                charts = r.json().get("charts", [])
                result = []
                for ch in charts:
                    sizes = []
                    for row in (ch.get("rows") or []):
                        sv = next((v.get("name","") for a in row.get("attributes",[])
                                   if a.get("id")=="SIZE" for v in a.get("values",[])), "")
                        if sv:
                            sizes.append(sv)
                    result.append({"id": str(ch["id"]), "name": ch.get("names",{}).get("MLA",""),
                                   "domain": ch.get("domain_id",""), "sizes": sizes})
                return {"charts": result}
            return {"charts": [], "error": r.status_code, "body": r.text[:200]}
    except Exception as e:
        import traceback
        return {"charts": [], "error": str(e), "trace": traceback.format_exc()[:500]}

@app.post("/api/duplicate/with_chart")
async def dup_with_chart(request: Request, _=Depends(auth)):
    """Guardar override de guía de talles para el duplicador"""
    b = await request.json()
    chart_override = b.get("chart_override", {})
    r = get_redis()
    if r and chart_override:
        r.set("mltn:chart_override", json.dumps(chart_override), ex=3600)
    return {"ok": True}


@app.get("/diag/charts_search")
async def diag_charts_search(domain: str = "BRAS", brand: str = "Maxima"):
    """Buscar guías de talles en cuenta destino (índice 1)"""
    try:
        to_t = await fresh_token(1)
        async with httpx.AsyncClient(timeout=15) as c:
            me_r = await c.get(f"{ML_API}/users/me", headers={"Authorization": f"Bearer {to_t}"})
            to_uid = me_r.json().get("id","")
            r = await c.post(f"{ML_API}/catalog/charts/search",
                headers={"Authorization": f"Bearer {to_t}", "Content-Type": "application/json"},
                json={"site_id":"MLA","seller_id": to_uid, "domain_id": domain,
                      "attributes":[
                          {"id":"GENDER","values":[{"name":"Mujer"}]},
                          {"id":"BRAND","values":[{"name":brand}]}
                      ]})
            return {"uid": to_uid, "domain": domain, "status": r.status_code, "body": r.json()}
    except Exception as e:
        return {"exception": str(e)}

@app.get("/diag/copy_chart/{chart_id}")
async def diag_copy_chart(chart_id: str):
    """Leer guía con token del dueño"""
    try:
        from_t = await fresh_token(0)
        to_t = await fresh_token(1)
        t2 = await fresh_token(2)
        async with httpx.AsyncClient(timeout=30) as c:
            r0 = await c.get(f"{ML_API}/catalog/charts/{chart_id}", headers={"Authorization": f"Bearer {from_t}"})
            r1 = await c.get(f"{ML_API}/catalog/charts/{chart_id}", headers={"Authorization": f"Bearer {to_t}"})
            r2 = await c.get(f"{ML_API}/catalog/charts/{chart_id}", headers={"Authorization": f"Bearer {t2}"})
            return {
                "with_account_0": {"status": r0.status_code, "chart": r0.json()},
                "with_account_1": {"status": r1.status_code, "chart": r1.json()},
                "with_account_2": {"status": r2.status_code, "chart": r2.json()},
            }
    except Exception as e:
        return {"exception": str(e)}

@app.get("/diag/chart_rows/{chart_id}")
async def diag_chart_rows(chart_id: str, acc: int = 2):
    """Ver rows de una guía de talles con cuenta específica"""
    try:
        t = await fresh_token(acc)
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(f"{ML_API}/catalog/charts/{chart_id}", headers={"Authorization": f"Bearer {t}"})
            if r.status_code != 200:
                return {"error": r.status_code, "body": r.text}
            chart = r.json()
            rows = []
            for row in (chart.get("rows") or []):
                rid = row.get("id", "")
                size_val = next((v.get("name","") for a in row.get("attributes",[])
                                 if a.get("id")=="SIZE" for v in a.get("values",[])), "")
                rows.append({"row_id": rid, "size": size_val, "raw": row})
            return {"chart_id": chart_id, "name": chart.get("names"), "domain": chart.get("domain_id"), "rows": rows}
    except Exception as e:
        return {"exception": str(e)}

@app.get("/diag/add_row/{chart_id}/{size_val}")
async def diag_add_row(chart_id: str, size_val: str, acc: int = 0):
    """Probar agregar un talle a una guía de talles"""
    try:
        t = await fresh_token(acc)
        async with httpx.AsyncClient(timeout=20) as c:
            # Intentar agregar el row
            r = await c.post(
                f"{ML_API}/catalog/charts/{chart_id}/rows",
                headers={"Authorization": f"Bearer {t}", "Content-Type": "application/json"},
                json={"attributes": [{"id": "SIZE", "values": [{"name": size_val}]}]}
            )
            return {
                "chart_id": chart_id,
                "size_val": size_val,
                "acc": acc,
                "status": r.status_code,
                "response": r.json() if r.content else {}
            }
    except Exception as e:
        return {"exception": str(e)}


@app.post("/api/duplicate/create_chart")
async def dup_create_chart(request: Request):
    """Crear guía de talles en cuenta destino copiando desde cuenta origen"""
    b = await request.json()
    orig_chart_id = b.get("orig_chart_id","")
    domain_id = b.get("domain_id","")
    brand = b.get("brand","")
    to_account = int(b.get("to_account", 1))
    try:
        from_t = await fresh_token(0)  # cuenta principal
        to_t = await fresh_token(to_account)
        async with httpx.AsyncClient(timeout=30) as c:
            # Leer guía original
            r = await c.get(f"{ML_API}/catalog/charts/{orig_chart_id}",
                           headers={"Authorization": f"Bearer {from_t}"})
            if r.status_code != 200:
                return {"ok": False, "msg": f"No se pudo leer la guía origen: {r.status_code}"}
            orig = r.json()
            # Crear en destino
            new_chart = {
                "names": orig.get("names", {"MLA": "Guía de talles"}),
                "domain_id": orig.get("domain_id") or domain_id,
                "site_id": "MLA",
                "main_attribute": {"attributes": [{"site_id": "MLA", "id": orig.get("main_attribute_id", "SIZE")}]},
                "attributes": orig.get("attributes", []),
                "rows": [{"attributes": r2.get("attributes",[])} for r2 in (orig.get("rows") or [])]
            }
            if orig.get("measure_type"):
                new_chart["measure_type"] = orig["measure_type"]
            r2 = await c.post(f"{ML_API}/catalog/charts",
                             headers={"Authorization": f"Bearer {to_t}", "Content-Type": "application/json"},
                             json=new_chart)
            if r2.status_code in (200, 201):
                new_id = r2.json().get("id","")
                return {"ok": True, "msg": f"Guía creada con ID {new_id}", "chart_id": new_id}
            return {"ok": False, "msg": f"Error al crear guía: {r2.status_code} — {r2.text[:200]}"}
    except Exception as e:
        return {"ok": False, "msg": str(e)}

@app.post("/api/duplicate/add_size")
async def dup_add_size(request: Request):
    """Agregar talle faltante a guía de talles en cuenta destino"""
    b = await request.json()
    chart_id = b.get("chart_id","")
    size_val = b.get("size_val","")
    to_account = int(b.get("to_account", 1))
    try:
        to_t = await fresh_token(to_account)
        # Leer guía completa para obtener atributos requeridos de otros rows
        async with httpx.AsyncClient(timeout=20) as c:
            gr = await c.get(f"{ML_API}/catalog/charts/{chart_id}",
                            headers={"Authorization": f"Bearer {to_t}"})
            if gr.status_code != 200:
                return {"ok": False, "msg": f"No se pudo leer la guía: {gr.status_code}"}
            chart_data = gr.json()
            # Copiar estructura de atributos del último row existente y cambiar SIZE
            existing_rows = chart_data.get("rows", [])
            if not existing_rows:
                return {"ok": False, "msg": "La guía no tiene rows existentes para copiar estructura"}
            # Usar el último row como template
            template = existing_rows[-1].get("attributes", [])
            new_attrs = []
            for a in template:
                if a.get("id") == "SIZE":
                    new_attrs.append({"id": "SIZE", "values": [{"name": size_val}]})
                elif a.get("id") == "FILTRABLE_SIZE":
                    # Mantener las equivalencias del template
                    new_attrs.append({"id": "FILTRABLE_SIZE", "values": a.get("values", [])})
                else:
                    # Incrementar levemente las medidas para evitar duplicados
                    vals = a.get("values", [])
                    new_vals = []
                    for v in vals:
                        if v.get("struct"):
                            new_num = v["struct"]["number"] + 5
                            new_vals.append({"name": f"{new_num} {v['struct']['unit']}", "struct": {"number": new_num, "unit": v["struct"]["unit"]}})
                        else:
                            new_vals.append(v)
                    new_attrs.append({"id": a["id"], "values": new_vals})
            add_r = await c.post(f"{ML_API}/catalog/charts/{chart_id}/rows",
                                headers={"Authorization": f"Bearer {to_t}", "Content-Type": "application/json"},
                                json={"attributes": new_attrs})
            if add_r.status_code in (200, 201):
                new_row_id = add_r.json().get("id","")
                return {"ok": True, "msg": f"Talle '{size_val}' agregado", "row_id": new_row_id}
            return {"ok": False, "msg": f"Error: {add_r.status_code} — {add_r.text[:300]}"}
    except Exception as e:
        return {"ok": False, "msg": str(e)}


@app.get("/diag/create_pijama_chart")
async def diag_create_pijama_chart(acc: int = 0):
    """Crear guía de talles de pijamas con XL-2XL y 3XL-4XL en cuenta destino"""
    try:
        t = await fresh_token(acc)
        async with httpx.AsyncClient(timeout=30) as c:
            payload = {
                "names": {"MLA": "Pijamas Mujer Talles Grandes"},
                "domain_id": "PAJAMAS",
                "site_id": "MLA",
                "main_attribute": {"attributes": [{"site_id": "MLA", "id": "SIZE"}]},
                "attributes": [{"id": "GENDER", "values": [{"id": "339665", "name": "Mujer"}]}],
                "rows": [
                    {"attributes": [
                        {"id": "SIZE", "values": [{"name": "XL-2XL"}]},
                        {"id": "FILTRABLE_SIZE", "values": [{"id": "12917787", "name": "XL"}, {"id": "12917846", "name": "2XL"}]},
                        {"id": "GARMENT_CHEST_WIDTH_FROM", "values": [{"name": "55 cm", "struct": {"number": 55.0, "unit": "cm"}}]},
                        {"id": "GARMENT_CHEST_WIDTH_TO", "values": [{"name": "65 cm", "struct": {"number": 65.0, "unit": "cm"}}]},
                        {"id": "GARMENT_HIP_WIDTH_FROM", "values": [{"name": "55 cm", "struct": {"number": 55.0, "unit": "cm"}}]},
                        {"id": "GARMENT_HIP_WIDTH_TO", "values": [{"name": "65 cm", "struct": {"number": 65.0, "unit": "cm"}}]},
                    ]},
                    {"attributes": [
                        {"id": "SIZE", "values": [{"name": "3XL-4XL"}]},
                        {"id": "FILTRABLE_SIZE", "values": [{"id": "12917837", "name": "3XL"}, {"id": "12918373", "name": "4XL"}]},
                        {"id": "GARMENT_CHEST_WIDTH_FROM", "values": [{"name": "66 cm", "struct": {"number": 66.0, "unit": "cm"}}]},
                        {"id": "GARMENT_CHEST_WIDTH_TO", "values": [{"name": "80 cm", "struct": {"number": 80.0, "unit": "cm"}}]},
                        {"id": "GARMENT_HIP_WIDTH_FROM", "values": [{"name": "66 cm", "struct": {"number": 66.0, "unit": "cm"}}]},
                        {"id": "GARMENT_HIP_WIDTH_TO", "values": [{"name": "80 cm", "struct": {"number": 80.0, "unit": "cm"}}]},
                    ]}
                ]
            }
            r = await c.post(f"{ML_API}/catalog/charts",
                            headers={"Authorization": f"Bearer {t}", "Content-Type": "application/json"},
                            json=payload)
            return {"status": r.status_code, "response": r.json()}
    except Exception as e:
        return {"exception": str(e)}


@app.get("/diag/sizecharts_cat/{category_id}")
async def diag_sizecharts_cat(category_id: str, brand: str = "", gender_id: str = ""):
    """Buscar guía de talles por marca como hace Astroselling"""
    try:
        from_t = await fresh_token(0)
        async with httpx.AsyncClient(timeout=30) as c:
            results = {}
            endpoints = [
                f"/size_charts/search?q={brand}&category_id={category_id}",
                f"/size_charts/search?brand={brand}&category_id={category_id}",
                f"/size_charts/search?q={brand}",
                f"/size_charts?q={brand}&category_id={category_id}",
                f"/size_charts?brand_name={brand}&category_id={category_id}",
            ]
            for ep in endpoints:
                r = await c.get(f"{ML_API}{ep}",
                    headers={"Authorization": f"Bearer {from_t}"})
                results[ep] = {"status": r.status_code, "body": r.text[:500]}
            return {"category_id": category_id, "brand": brand, "results": results}
    except Exception as e:
        return {"exception": str(e)}


async def diag_sizechart(item_id: str):
    if len(ST["accounts"]) < 2:
        return {"error": "Necesitás 2 cuentas"}
    try:
        from_t = await fresh_token(0)
        to_t = await fresh_token(1)
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(f"{ML_API}/items/{item_id}", headers={"Authorization": f"Bearer {from_t}"})
            item = r.json()
            cat_id = item.get("category_id","")
            size_attr = next((a for a in (item.get("attributes") or []) if a.get("id")=="SIZE_GRID_ID"), None)
            chart_id = size_attr.get("value_name") or size_attr.get("value_id") if size_attr else None
            to_uid_r = await c.get(f"{ML_API}/users/me", headers={"Authorization": f"Bearer {to_t}"})
            to_uid = to_uid_r.json().get("id")
            results = {}
            endpoints = [
                f"/size_charts/{chart_id}",
                f"/size_charts/search?category_id={cat_id}",
                f"/users/{to_uid}/size_charts",
                f"/size_charts?category_id={cat_id}&seller_id={to_uid}",
                f"/size_charts?seller_id={to_uid}",
            ]
            for ep in endpoints:
                r2 = await c.get(f"{ML_API}{ep}", headers={"Authorization": f"Bearer {to_t}"})
                results[ep] = {"status": r2.status_code, "body": r2.text[:300]}
            return {"category_id": cat_id, "chart_id": chart_id, "dest_uid": to_uid, "results": results}
    except Exception as e:
        return {"exception": str(e)}

@app.get("/diag/testdup/{item_id}")
async def diag_testdup(item_id: str):
    if len(ST["accounts"]) < 2:
        return {"error": "Necesitás 2 cuentas"}
    try:
        from_t = await fresh_token(0)
        to_t = await fresh_token(1)
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(f"{ML_API}/items/{item_id}", headers={"Authorization": f"Bearer {from_t}"})
            item = r.json()
            if "title" not in item:
                return {"error": "ML no devolvió el item", "http_status": r.status_code, "response": item}
            SKIP = {"SELLER_SKU","ITEM_CONDITION","ALPHANUMERIC_MODEL","GTIN",
                    "PACKAGE_DATA_SOURCE","RELEASE_YEAR","SYI_PYMES_ID",
                    "FILTRABLE_SIZE","SIZE_GRID_ROW_ID","SIZE_GRID_ID"}
            attrs = []
            brand_name = ""
            model_name = ""
            # Primero extraer BRAND y MODEL
            for a in (item.get("attributes") or []):
                if a.get("id") == "BRAND": brand_name = a.get("value_name","")
                if a.get("id") == "MODEL": model_name = a.get("value_name","")
            # Armar atributos
            for a in (item.get("attributes") or []):
                aid = a.get("id","")
                if aid in SKIP: continue
                if aid in ("BRAND","MODEL"):
                    vn = a.get("value_name")
                    if vn: attrs.append({"id":aid,"value_name":vn})
                    continue
                if aid == "SIZE_GRID_ID":
                    vn = a.get("value_name") or a.get("value_id")
                    if vn: attrs.append({"id":"SIZE_GRID_ID","value_name":str(vn)})
                    continue
                if a.get("value_id"): attrs.append({"id":aid,"value_id":a["value_id"]})
                elif a.get("value_name"): attrs.append({"id":aid,"value_name":a["value_name"]})
            # family_name SIEMPRE requerido por ML
            # Título base: cortar todo lo que viene DESPUÉS del número de modelo en el título
            raw_title = item.get("title","")
            if model_name and model_name in raw_title:
                idx = raw_title.index(model_name) + len(model_name)
                clean_title = raw_title[:idx].strip()
            elif " - " in raw_title:
                clean_title = raw_title.rsplit(" - ", 1)[0].strip()
            else:
                clean_title = raw_title.strip()
            # ML acepta máximo 60 chars pero a veces falla con exactamente 60, usar 59
            clean_title = clean_title[:59].strip()
            import unicodedata
            def strip_accents(s):
                return ''.join(c for c in unicodedata.normalize('NFD', s) if unicodedata.category(c) != 'Mn')
            test_title = strip_accents(clean_title)
            family = model_name or brand_name or clean_title
            # Detectar listing types disponibles para la cuenta destino
            to_uid_r = await c.get(f"{ML_API}/users/me", headers={"Authorization": f"Bearer {to_t}"})
            to_uid = to_uid_r.json().get("id")
            lt_r = await c.get(f"{ML_API}/users/{to_uid}/available_listing_types?category_id={item.get('category_id','')}", 
                               headers={"Authorization": f"Bearer {to_t}"})
            available_lts = [x.get("id") for x in (lt_r.json() if isinstance(lt_r.json(), list) else [])]
            # Usar el mismo listing type del item original si está disponible, si no el mejor disponible
            orig_lt = item.get("listing_type_id","gold_special")
            listing_type = orig_lt if orig_lt in available_lts else (available_lts[0] if available_lts else "gold_special")
            # Verificar si cuenta destino tiene user_product_seller tag
            me_r2 = await c.get(f"{ML_API}/users/{to_uid}", headers={"Authorization": f"Bearer {to_t}"})
            dest_tags = me_r2.json().get("tags", [])
            # SHAMPOOSHIR es user_product_seller — usar modelo nuevo sin title
            # Usar todos los atributos del item original
            up_attrs = []
            for a in (item.get("attributes") or []):
                aid = a.get("id","")
                if aid in ("SELLER_SKU","ITEM_CONDITION","ALPHANUMERIC_MODEL","GTIN",
                           "PACKAGE_DATA_SOURCE","RELEASE_YEAR","SYI_PYMES_ID","FILTRABLE_SIZE"):
                    continue
                if aid == "SIZE":
                    # Para user_product_seller SIZE va como value_name
                    vn = a.get("value_name") or str(a.get("value_id",""))
                    if vn: up_attrs.append({"id":"SIZE","value_name":vn})
                    continue
                if aid == "SIZE_GRID_ID":
                    up_attrs.append({"id":"SIZE_GRID_ID","value_name":"2556917"})
                    continue
                if a.get("value_id"):
                    up_attrs.append({"id":aid,"value_id":a["value_id"]})
                elif a.get("value_name"):
                    up_attrs.append({"id":aid,"value_name":a["value_name"]})
            payload = {
                "family_name": "Pack X3 Corpino Reductor De Algodon Liso Bretel Ancho 1018",
                "category_id": item.get("category_id",""),
                "price": item.get("price",0),
                "currency_id": item.get("currency_id","ARS"),
                "available_quantity": item.get("available_quantity",0),
                "listing_type_id": "gold_special",
                "condition": item.get("condition","new"),
                "pictures": [{"source": p["url"].replace("http://","https://")} for p in (item.get("pictures") or [])[:6]],
                "attributes": up_attrs,
            }
            # Mapa correcto SIZE → ROW_ID para guía 2556917 de SHAMPOOSHIR
            CHART_2556917 = {
                "S/M":"2556917:1","85":"2556917:5","90":"2556917:6","L/XL":"2556917:2",
                "95":"2556917:7","100":"2556917:8","2XL":"2556917:3","105":"2556917:9",
                "110":"2556917:10","3XL":"2556917:4","115":"2556917:11","120":"2556917:12","125":"2556917:13"
            }
            size_val = next((x.get("value_name","") for x in payload["attributes"] if x.get("id")=="SIZE"), "")
            for i, a in enumerate(payload["attributes"]):
                if a.get("id") == "SIZE_GRID_ROW_ID":
                    mapped = CHART_2556917.get(size_val)
                    if mapped:
                        payload["attributes"][i] = {"id":"SIZE_GRID_ROW_ID","value_name":mapped}
                    break
            r2 = await c.post(f"{ML_API}/items", headers={"Authorization": f"Bearer {to_t}"}, json=payload)
            resp = r2.json()
            if r2.status_code in (200,201):
                new_id = resp.get("id")
                await c.delete(f"{ML_API}/items/{new_id}", headers={"Authorization": f"Bearer {to_t}"})
                return {"result": "✅ FUNCIONA sin SIZE_GRID_ID", "new_id": new_id}
            return {"result": "❌ FALLA", "status": r2.status_code, 
                    "causes": resp.get("cause",[]), 
                    "message": resp.get("message"),
                    "title_sent": clean_title,
                    "title_length": len(clean_title),
                    "listing_type_used": listing_type,
                    "available_listing_types": available_lts,
                    "dest_tags": dest_tags,
                    "payload_sent": payload,
                    "full_error": resp}
    except Exception as e:
        return {"exception": str(e)}

@app.get("/diag")
async def diag():
    r = get_redis()
    redis_ok = False
    try:
        if r: r.ping(); redis_ok = True
    except: pass
    result = {"redis": redis_ok, "accounts": len(ST["accounts"]), "accounts_detail": []}
    for i, acc in enumerate(ST["accounts"]):
        token = acc.get("token","")
        expired = time.time() > acc.get("expiry",0)
        detail = {
            "index": i,
            "name": acc.get("name",""),
            "token_preview": token[:20]+"..." if token else "EMPTY",
            "token_expired": expired,
        }
        if not expired and token:
            try:
                async with httpx.AsyncClient(timeout=10) as c:
                    r2 = await c.get(f"{ML_API}/users/me", headers={"Authorization":f"Bearer {token}"})
                    detail["ml_status"] = r2.status_code
                    detail["ml_uid"] = r2.json().get("id") if r2.status_code==200 else r2.text[:100]
            except Exception as e:
                detail["ml_error"] = str(e)
        result["accounts_detail"].append(detail)
    return result

fp = Path("frontend")
if fp.exists():
    from fastapi import Response
    from fastapi.responses import FileResponse
    import os

    @app.get("/manifest.json")
    async def serve_manifest():
        return FileResponse(str(fp / "manifest.json"), media_type="application/manifest+json")

    @app.get("/sw.js")
    async def serve_sw():
        return FileResponse(str(fp / "sw.js"), media_type="application/javascript", headers={"Service-Worker-Allowed": "/"})

    @app.get("/icon-192.png")
    async def serve_icon192():
        return FileResponse(str(fp / "icon-192.png"), media_type="image/png")

    @app.get("/icon-512.png")
    async def serve_icon512():
        return FileResponse(str(fp / "icon-512.png"), media_type="image/png")

    @app.get("/")
    async def serve_index():
        return FileResponse(str(fp / "index.html"))

    @app.get("/{full_path:path}")
    async def serve_static(full_path: str):
        # No interceptar rutas de API ni diag
        if full_path.startswith("api/") or full_path.startswith("diag"):
            from fastapi import HTTPException
            raise HTTPException(404)
        file_path = fp / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(str(file_path))
        # Fallback a index.html para SPA
        return FileResponse(str(fp / "index.html"))
