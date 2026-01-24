from fastapi import FastAPI

app = FastAPI()


@app.post("/v1/liveness/extract_best_frame")
async def extract_best_frame(payload: dict):
    return {"status": "ok", "best_frame_key": payload.get("key", "")}


@app.post("/v1/document/extract_portrait")
async def extract_portrait(payload: dict):
    return {"status": "ok", "portrait_key": payload.get("key", "")}

