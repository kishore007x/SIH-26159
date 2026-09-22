from fastapi import FastAPI
from backend.app.routes import router

app = FastAPI(title="SecureMailScope", version="1.0.0")
app.include_router(router, prefix="/api")


@app.get("/health")
async def health():
    return {"status": "healthy", "version": "1.0.0"}
@app.get("/")
async def root():
    return {"message": "SecureMailScope API"}