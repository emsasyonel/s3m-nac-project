from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse # YENİ EKLENDİ
from pydantic import BaseModel
from contextlib import asynccontextmanager
import bcrypt
import database
from datetime import datetime, timezone

def get_password_hash(password: str) -> str:
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        return False

def get_radius_val(data, key, default=None):
    val = data.get(key)
    if not val: return default
    if isinstance(val, dict) and 'value' in val: val = val['value']
    if isinstance(val, list): return val[0] if val else default
    return val

class UserCreate(BaseModel):
    username: str
    password: str
    groupname: str = "guest"
    mac_address: str | None = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    await database.init_db()
    await database.init_redis()
    yield
    await database.close_db()
    await database.close_redis()

app = FastAPI(title="S3M NAC Policy Engine", lifespan=lifespan)

@app.post("/users", status_code=201)
async def create_user(user: UserCreate):
    pool = database.get_db()
    async with pool.acquire() as conn:
        exists = await conn.fetchval("SELECT id FROM radcheck WHERE username = $1", user.username)
        if exists: raise HTTPException(status_code=400, detail="Bu kullanıcı adı zaten kayıtlı.")
        
        hashed_password = get_password_hash(user.password)
        await conn.execute("INSERT INTO radcheck (username, attribute, op, value) VALUES ($1, 'Bcrypt-Password', ':=', $2)", user.username, hashed_password)
        await conn.execute("INSERT INTO radusergroup (username, groupname, priority) VALUES ($1, $2, 1)", user.username, user.groupname)
    return {"message": "Kullanici basariyla olusturuldu", "username": user.username, "group": user.groupname}

@app.get("/users")
async def get_users():
    pool = database.get_db()
    async with pool.acquire() as conn:
        records = await conn.fetch("SELECT c.username, g.groupname FROM radcheck c LEFT JOIN radusergroup g ON c.username = g.username WHERE c.attribute = 'Bcrypt-Password'")
        users_list = [{"username": rec["username"], "group": rec["groupname"]} for rec in records]
    return {"status": "ok", "total": len(users_list), "users": users_list}

@app.post("/auth")
async def authenticate_user(request: Request):
    data = await request.json()
    
    username = get_radius_val(data, "User-Name")
    # DÜZELTME 1: FreeRADIUS'un değiştirdiği şifre adını da yakalıyoruz
    password = get_radius_val(data, "User-Password") or get_radius_val(data, "Cleartext-Password")
    mac_address = get_radius_val(data, "Calling-Station-Id")

    if not username:
        return JSONResponse(status_code=401, content={"reply:Reply-Message": "Kullanici adi gerekli"})

    redis_client = database.get_redis_client()
    failed_attempts_key = f"failed_auth:{username}"
    
    attempts = await redis_client.get(failed_attempts_key)
    if attempts and int(attempts) >= 3:
        # DÜZELTME 2: Gerçek HTTP 401 dönüyoruz
        return JSONResponse(status_code=401, content={"reply:Reply-Message": "Cok fazla hatali deneme. Lutfen 5 dakika bekleyin."})

    pool = database.get_db()
    async with pool.acquire() as conn:
        record = await conn.fetchrow("SELECT value FROM radcheck WHERE username = $1 AND attribute = 'Bcrypt-Password'", username)
        if record:
            hashed_pw = record['value']
            # DÜZELTME 3: Password boş gelmediğinden emin oluyoruz
            if password and verify_password(password, hashed_pw):
                await redis_client.delete(failed_attempts_key)
                return JSONResponse(status_code=200, content={"reply:Reply-Message": "Kimlik Dogrulama Basarili"})
        
        await redis_client.incr(failed_attempts_key)
        await redis_client.expire(failed_attempts_key, 300)
        return JSONResponse(status_code=401, content={"reply:Reply-Message": "Gecersiz kimlik bilgileri"})

@app.post("/authorize")
async def authorize_user(request: Request):
    data = await request.json()
    username = get_radius_val(data, "User-Name")

    if not username: return JSONResponse(status_code=401, content={})

    pool = database.get_db()
    async with pool.acquire() as conn:
        record = await conn.fetchrow("SELECT groupname FROM radusergroup WHERE username = $1", username)
        groupname = record['groupname'] if record else "guest"
        vlan_id = "10" if groupname == "admin" else "20" if groupname == "employee" else "30"

        return JSONResponse(status_code=200, content={
            "reply:Tunnel-Type": "13",
            "reply:Tunnel-Medium-Type": "6",
            "reply:Tunnel-Private-Group-Id": vlan_id,
            "reply:Reply-Message": f"Sisteme hosgeldiniz, Grubunuz: {groupname}, VLAN: {vlan_id}"
        })

@app.post("/accounting")
async def handle_accounting(request: Request):
    return JSONResponse(status_code=200, content={"code": 200})