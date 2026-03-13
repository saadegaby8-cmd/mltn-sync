from fastapi import FastAPI, HTTPException, Request, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import httpx, asyncio, json, os, time, secrets
from pathlib import Path

app = FastAPI()
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
                save_state()
        except:
            pass
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
        return {"products": products, "total": total, "synced": True, "page": 1, "limit": total}
    start = (page-1)*limit
    page_products = products[start:start+limit]
    return {"products": page_products, "total": total, "synced": True, "page": page, "limit": limit}

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

    # Publicar en TiendaNube (comportamiento original)
    if not ST["tn"].get("store_id"):
        raise HTTPException(400, "TN no conectada.")
    token = await fresh_token(idx)
    ml_hdrs = {"Authorization": f"Bearer {token}"}
    tn = ST["tn"]
    tn_hdrs = {"Authentication":f"bearer {tn['token']}","Content-Type":"application/json"}
    results = []
    for iid in item_ids:
        try:
            async with httpx.AsyncClient(timeout=20) as c:
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
    from_t = await fresh_token(b.get("from_account",0))
    to_t = await fresh_token(b.get("to_account",1))
    results = []
    async with httpx.AsyncClient(timeout=30) as c:
        for iid in b.get("item_ids",[]):
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
            results.append({"id":iid,"title":item.get("title",""),"ok":ok})
            await asyncio.sleep(0.5)
    return {"results": results}

@app.get("/diag")
async def diag():
    r = get_redis()
    redis_ok = False
    try:
        if r: r.ping(); redis_ok = True
    except: pass
    result = {"redis": redis_ok, "accounts": len(ST["accounts"])}
    if ST["accounts"]:
        acc = ST["accounts"][0]
        token = acc.get("token","")
        result["token_preview"] = token[:20]+"..." if token else "EMPTY"
        result["token_expired"] = time.time() > acc.get("expiry",0)
        async with httpx.AsyncClient(timeout=10) as c:
            r2 = await c.get(f"{ML_API}/users/me", headers={"Authorization":f"Bearer {token}"})
            result["ml_status"] = r2.status_code
            result["ml_body"] = r2.text[:300]
    return result

fp = Path("frontend")
if fp.exists():
    app.mount("/", StaticFiles(directory=str(fp), html=True), name="static")
