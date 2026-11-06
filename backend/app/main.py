
from fastapi import FastAPI
from datetime import datetime, timezone

app = FastAPI(
    title="ProofBox AI",
    description="Secure AI-powered code execution platform",
    version="0.1.0"
)


@app.get("/")
def root():
    return {
        "project": "ProofBox AI",
        "message": "Secure code execution platform",
        "status": "running"
    }


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "service": "proofbox-backend",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/info")
def info():
    return {
        "name": "ProofBox AI",
        "version": "0.1.0",
        "execution_engine": "not_configured",
        "ai_provider": "not_configured"
    }
