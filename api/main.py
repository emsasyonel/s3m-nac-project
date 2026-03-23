from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from contextlib import asynccontextmanager
import bcrypt
import database
from datetime import datetime, timezone

def get_password_hash(password: str) -> str:
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(pwd_bytes, salt)
    return hashed_password.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        return False

# YENİ EKLENEN FİLTRE FONKSİYONU
def get_radius_val(data, key, default=None):
    """FreeRADIUS'tan gelen karmaşık JSON verisini temizler ve düz metin döner"""
    val = data.get(key)
    if not val:
        return default
    # Eğer FreeRADIUS dict olarak gönderdiyse {'type': 'string', 'value': ['admin']}
    if isinstance(val, dict) and 'value' in val:
        val = val['value']
    # Eğer FreeRADIUS liste olarak gönderdiyse ['admin']
    if isinstance(val, list):
        return val[0] if val else default
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
        if exists:
            raise HTTPException(status_code=400, detail="Bu kullanıcı adı zaten kayıtlı.")
        
        hashed_password = get_password_hash(user.password)
        await conn.execute("INSERT INTO radcheck (username, attribute, op, value) VALUES ($1, 'Bcrypt-Password', ':=', $2)", user.username, hashed_password)
        await conn.execute("INSERT INTO radusergroup (username, groupname, priority) VALUES ($1, $2, 1)", user.username, user.groupname)
        
        if user.mac_address:
            await conn.execute("INSERT INTO radcheck (username, attribute, op, value) VALUES ($1, 'Calling-Station-Id', '==', $2)", user.username, user.mac_address)
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
    
    # ARTIK DEĞERLERİ FİLTRE FONKSİYONUMUZLA ALIYORUZ
    username = get_radius_val(data, "User-Name")
    password = get_radius_val(data, "User-Password")
    mac_address = get_radius_val(data, "Calling-Station-Id")

    if not username:
        return {"code": 401, "reply:Reply-Message": "Kullanici adi gerekli"}

    redis_client = database.get_redis_client()
    failed_attempts_key = f"failed_auth:{username}"
    
    attempts = await redis_client.get(failed_attempts_key)
    if attempts and int(attempts) >= 3:
        return {"code": 401, "reply:Reply-Message": "Cok fazla hatali deneme. Lutfen 5 dakika bekleyin."}

    pool = database.get_db()
    async with pool.acquire() as conn:
        if not password and mac_address:
            record = await conn.fetchrow("SELECT value FROM radcheck WHERE username = $1 AND attribute = 'Calling-Station-Id'", username)
            if record and record['value'] == mac_address:
                return {"code": 200, "reply:Reply-Message": "MAB Dogrulama Basarili"}
            return {"code": 401, "reply:Reply-Message": "Bilinmeyen MAC Adresi"}

        record = await conn.fetchrow("SELECT value FROM radcheck WHERE username = $1 AND attribute = 'Bcrypt-Password'", username)
        if record:
            hashed_pw = record['value']
            if verify_password(password, hashed_pw):
                await redis_client.delete(failed_attempts_key)
                return {"code": 200, "reply:Reply-Message": "Kimlik Dogrulama Basarili"}
        
        await redis_client.incr(failed_attempts_key)
        await redis_client.expire(failed_attempts_key, 300)
        return {"code": 401, "reply:Reply-Message": "Gecersiz kimlik bilgileri"}

@app.post("/authorize")
async def authorize_user(request: Request):
    data = await request.json()
    username = get_radius_val(data, "User-Name")

    if not username:
        return {"code": 401}

    pool = database.get_db()
    async with pool.acquire() as conn:
        record = await conn.fetchrow("SELECT groupname FROM radusergroup WHERE username = $1", username)
        groupname = record['groupname'] if record else "guest"
        vlan_id = "30"
        if groupname == "admin": vlan_id = "10"
        elif groupname == "employee": vlan_id = "20"

        return {
            "code": 200,
            "reply:Tunnel-Type": "13",
            "reply:Tunnel-Medium-Type": "6",
            "reply:Tunnel-Private-Group-Id": vlan_id,
            "reply:Reply-Message": f"Sisteme hosgeldiniz, Grubunuz: {groupname}, VLAN: {vlan_id}"
        }

@app.post("/accounting")
async def handle_accounting(request: Request):
    data = await request.json()
    
    status_type = get_radius_val(data, "Acct-Status-Type")
    session_id = get_radius_val(data, "Acct-Session-Id")
    username = get_radius_val(data, "User-Name", "unknown")
    nas_ip = get_radius_val(data, "NAS-IP-Address", "0.0.0.0")
    
    try: input_octets = int(get_radius_val(data, "Acct-Input-Octets", 0))
    except: input_octets = 0
    try: output_octets = int(get_radius_val(data, "Acct-Output-Octets", 0))
    except: output_octets = 0
    try: session_time = int(get_radius_val(data, "Acct-Session-Time", 0))
    except: session_time = 0
    
    if not status_type or not session_id:
        return {"code": 400, "message": "Eksik parametreler"}

    pool = database.get_db()
    redis_client = database.get_redis_client()
    now = datetime.now(timezone.utc)
    
    async with pool.acquire() as conn:
        if status_type == "Start":
            await conn.execute("INSERT INTO radacct (acctsessionid, username, nasipaddress, acctstarttime, acctinputoctets, acctoutputoctets) VALUES ($1, $2, $3, $4, $5, $6)", session_id, username, nas_ip, now, input_octets, output_octets)
            session_data = {"username": username, "nas_ip": nas_ip, "start_time": now.isoformat()}
            await redis_client.hset(f"session:{session_id}", mapping=session_data)
            await redis_client.sadd("active_sessions", session_id)
        elif status_type == "Interim-Update":
            await conn.execute("UPDATE radacct SET acctupdatetime = $1, acctinputoctets = $2, acctoutputoctets = $3, acctsessiontime = $4 WHERE acctsessionid = $5", now, input_octets, output_octets, session_time, session_id)
        elif status_type == "Stop":
            await conn.execute("UPDATE radacct SET acctstoptime = $1, acctinputoctets = $2, acctoutputoctets = $3, acctsessiontime = $4 WHERE acctsessionid = $5", now, input_octets, output_octets, session_time, session_id)
            await redis_client.delete(f"session:{session_id}")
            await redis_client.srem("active_sessions", session_id)

    return {"code": 200}

@app.get("/sessions/active")
async def get_active_sessions():
    redis_client = database.get_redis_client()
    session_ids = await redis_client.smembers("active_sessions")
    sessions = []
    for sid in session_ids:
        data = await redis_client.hgetall(f"session:{sid}")
        if data:
            data["session_id"] = sid
            sessions.append(data)
    return {"status": "ok", "total": len(sessions), "sessions": sessions}