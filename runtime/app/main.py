from fastapi import FastAPI

app = FastAPI(title="AgentShield Runtime")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "runtime"}
