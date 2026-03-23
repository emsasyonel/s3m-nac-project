from fastapi import FastAPI, Request, HTTPException, Depends
from pydantic import BaseModel
from contextlib import asynccontextmanager
from passlib.context import CryptContext
import database

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

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
    return {"code": 401, "reply:Reply-Message": "Authentication not implemented yet"}

@app.post("/authorize")
async def authorize_user(request: Request):
    return {"code": 200}

@app.post("/accounting")
async def handle_accounting(request: Request):
    return {"code": 200}

@app.get("/sessions/active")
async def get_active_sessions():
    return {"status": "ok", "sessions": []}