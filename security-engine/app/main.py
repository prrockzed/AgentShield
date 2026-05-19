from fastapi import FastAPI

app = FastAPI(title="AgentShield Security Engine")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "security-engine"}
