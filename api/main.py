from fastapi import FastAPI

app = FastAPI(title="S3M NAC Policy Engine")

@app.get("/")
async def root():
    return {"status": "ok", "message": "NAC Policy Engine is running"}

@app.get("/users")
async def get_users():
    return []