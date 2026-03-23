import os
import asyncpg
import redis.asyncio as redis
from dotenv import load_dotenv

load_dotenv()

DB_USER = os.getenv("POSTGRES_USER", "nac_admin")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "your_secure_password")
DB_NAME = os.getenv("POSTGRES_DB", "nac_db")
DB_HOST = "postgres"  

REDIS_HOST = os.getenv("REDIS_HOST", "redis")  
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))

db_pool = None
redis_client = None

async def init_db():
    global db_pool
    db_pool = await asyncpg.create_pool(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        host=DB_HOST
    )

async def init_redis():
    global redis_client
    redis_client = redis.Redis(
        host=REDIS_HOST, 
        port=REDIS_PORT, 
        decode_responses=True 
    )

async def close_db():
    if db_pool:
        await db_pool.close()

async def close_redis():
    if redis_client:
        await redis_client.close()

def get_db():
    return db_pool

def get_redis_client():
    return redis_client