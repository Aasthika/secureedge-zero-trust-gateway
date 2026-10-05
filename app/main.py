from fastapi import FastAPI

app = FastAPI(
    title="SecureEdge",
    description="Zero-Trust API Gateway & Policy Enforcement Platform",
    version="0.1.0",
)


@app.get("/")
async def root():
    return {
        "service": "SecureEdge",
        "status": "running",
        "version": "0.1.0",
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
    }
