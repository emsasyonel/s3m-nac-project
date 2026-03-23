from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from contextlib import asynccontextmanager
import bcrypt
import database

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
    return {"code": 200}

@app.post("/accounting")
async def handle_accounting(request: Request):
    return {"code": 200}

@app.get("/sessions/active")
async def get_active_sessions():
    return {"status": "ok", "sessions": []}