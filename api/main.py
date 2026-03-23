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
    """Kullanıcının girdiği şifreyi, veritabanındaki hash ile karşılaştırır."""
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'), 
            hashed_password.encode('utf-8')
        )
    except ValueError:
        return False

class UserCreate(BaseModel):
    username: str
    password: str
    groupname: str = "guest"  
    mac_address: str | None = None  

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Veritabanı ve Redis bağlantıları başlatılıyor...")
    await database.init_db()
    await database.init_redis()
    yield
    print("Bağlantılar kapatılıyor...")
    await database.close_db()
    await database.close_redis()

app = FastAPI(title="S3M NAC Policy Engine", lifespan=lifespan)


@app.post("/users", status_code=201)
async def create_user(user: UserCreate):
    """Yeni kullanıcı (veya MAC cihazı) ekler ve şifresini hash'ler."""
    pool = database.get_db()
    async with pool.acquire() as conn:
        exists = await conn.fetchval("SELECT id FROM radcheck WHERE username = $1", user.username)
        if exists:
            raise HTTPException(status_code=400, detail="Bu kullanıcı adı zaten kayıtlı.")

        hashed_password = get_password_hash(user.password)

        await conn.execute(
            "INSERT INTO radcheck (username, attribute, op, value) VALUES ($1, 'Bcrypt-Password', ':=', $2)",
            user.username, hashed_password
        )

        await conn.execute(
            "INSERT INTO radusergroup (username, groupname, priority) VALUES ($1, $2, 1)",
            user.username, user.groupname
        )

        if user.mac_address:
            await conn.execute(
                "INSERT INTO radcheck (username, attribute, op, value) VALUES ($1, 'Calling-Station-Id', '==', $2)",
                user.username, user.mac_address
            )

    return {"message": "Kullanici basariyla olusturuldu", "username": user.username, "group": user.groupname}

@app.get("/users")
async def get_users():
    """Tüm kullanıcıları ve gruplarını listeler."""
    pool = database.get_db()
    async with pool.acquire() as conn:
        query = """
            SELECT c.username, g.groupname 
            FROM radcheck c
            LEFT JOIN radusergroup g ON c.username = g.username
            WHERE c.attribute = 'Bcrypt-Password'
        """
        records = await conn.fetch(query)
        
        users_list = [{"username": rec["username"], "group": rec["groupname"]} for rec in records]

    return {"status": "ok", "total": len(users_list), "users": users_list}



@app.post("/auth")
async def authenticate_user(request: Request):
    """Kullanıcı doğrulama ve sonuç dönme"""
    data = await request.json()
    
    username = data.get("User-Name")
    password = data.get("User-Password")
    mac_address = data.get("Calling-Station-Id")

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
            record = await conn.fetchrow(
                "SELECT value FROM radcheck WHERE username = $1 AND attribute = 'Calling-Station-Id'",
                username
            )
            if record and record['value'] == mac_address:
                return {"code": 200, "reply:Reply-Message": "MAB Dogrulama Basarili"}
            else:
                return {"code": 401, "reply:Reply-Message": "Bilinmeyen MAC Adresi"}

        record = await conn.fetchrow(
            "SELECT value FROM radcheck WHERE username = $1 AND attribute = 'Bcrypt-Password'",
            username
        )

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
    """VLAN, policy atribütleri dönme"""
    data = await request.json()
    username = data.get("User-Name")

    if not username:
        return {"code": 401}

    pool = database.get_db()
    async with pool.acquire() as conn:
        record = await conn.fetchrow(
            "SELECT groupname FROM radusergroup WHERE username = $1",
            username
        )

        groupname = record['groupname'] if record else "guest"

        vlan_id = "30"  
        
        if groupname == "admin":
            vlan_id = "10" 
        elif groupname == "employee":
            vlan_id = "20"  

        return {
            "code": 200,
            "reply:Tunnel-Type": "13",         
            "reply:Tunnel-Medium-Type": "6",      
            "reply:Tunnel-Private-Group-Id": vlan_id, 
            "reply:Reply-Message": f"Sisteme hosgeldiniz, Grubunuz: {groupname}, VLAN: {vlan_id}"
        }
    

@app.post("/accounting")
async def handle_accounting(request: Request):
    """Oturum verisi kaydetme (Start, Update, Stop)"""
    data = await request.json()
    
    # RADIUS paketinden gelen verileri yakala
    status_type = data.get("Acct-Status-Type")
    session_id = data.get("Acct-Session-Id")
    username = data.get("User-Name", "unknown")
    nas_ip = data.get("NAS-IP-Address", "0.0.0.0")
    
    # Gelen veri miktarı ve süresi (Yoksa 0 kabul et)
    input_octets = int(data.get("Acct-Input-Octets", 0))
    output_octets = int(data.get("Acct-Output-Octets", 0))
    session_time = int(data.get("Acct-Session-Time", 0))
    
    if not status_type or not session_id:
        return {"code": 400, "message": "Eksik parametreler"}

    pool = database.get_db()
    redis_client = database.get_redis_client()
    now = datetime.now(timezone.utc)
    
    async with pool.acquire() as conn:
        if status_type == "Start":
            # 1. Oturum Başlangıcı: Postgres'e yeni kayıt ekle
            await conn.execute("""
                INSERT INTO radacct 
                (acctsessionid, username, nasipaddress, acctstarttime, acctinputoctets, acctoutputoctets) 
                VALUES ($1, $2, $3, $4, $5, $6)
            """, session_id, username, nas_ip, now, input_octets, output_octets)
            
            # 2. Redis'e aktif oturum olarak kaydet
            session_data = {
                "username": username,
                "nas_ip": nas_ip,
                "start_time": now.isoformat()
            }
            await redis_client.hset(f"session:{session_id}", mapping=session_data)
            await redis_client.sadd("active_sessions", session_id)
            
        elif status_type == "Interim-Update":
            # Ara Güncelleme (Kullanıcı hala içeride, kota/süre güncelleniyor)
            await conn.execute("""
                UPDATE radacct 
                SET acctupdatetime = $1, acctinputoctets = $2, acctoutputoctets = $3, acctsessiontime = $4
                WHERE acctsessionid = $5
            """, now, input_octets, output_octets, session_time, session_id)
            
        elif status_type == "Stop":
            # 1. Oturum Bitişi: Postgres'teki kaydı sonlandır
            await conn.execute("""
                UPDATE radacct 
                SET acctstoptime = $1, acctinputoctets = $2, acctoutputoctets = $3, acctsessiontime = $4
                WHERE acctsessionid = $5
            """, now, input_octets, output_octets, session_time, session_id)
            
            # 2. Redis'ten (Aktif oturumlar listesinden) sil
            await redis_client.delete(f"session:{session_id}")
            await redis_client.srem("active_sessions", session_id)

    # İşlem başarılıysa FreeRADIUS'a boş/başarılı bir yanıt dön (Accounting onayı)
    return {"code": 200}

@app.get("/sessions/active")
async def get_active_sessions():
    """Aktif oturumları Redis üzerinden hızlıca sorgular"""
    redis_client = database.get_redis_client()
    session_ids = await redis_client.smembers("active_sessions")
    
    sessions = []
    for sid in session_ids:
        # Her bir oturum detayını Redis'ten çek
        data = await redis_client.hgetall(f"session:{sid}")
        if data:
            data["session_id"] = sid
            sessions.append(data)
        
    return {"status": "ok", "total": len(sessions), "sessions": sessions}