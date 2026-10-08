from fastapi import FastAPI, HTTPException
from fastapi.responses import Response

from .fixture import object_get

app = FastAPI(title="Release Metadata Service", version="0.1.0")


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/{path:path}")
def get_object(path: str):
    try:
        data, revision = object_get(path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="not found") from exc
    media_type = "application/json" if path.endswith(".json") else "application/octet-stream"
    return Response(
        content=data,
        media_type=media_type,
        headers={"ETag": revision, "Cache-Control": "no-store"},
    )
