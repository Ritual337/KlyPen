from __future__ import annotations
import os
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")

app = FastAPI(title="KlyPen Local Demo Lab")

PAGE = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>KlyPen Lab</title></head><body>
<h1>KlyPen local demo lab</h1><p>This intentionally simplified local-only page demonstrates passive scanner findings. Never expose this app to a network.</p>
<form method="post" action="http://127.0.0.1:9001/submit"><label>Demo password <input type="password" name="demo_password"></label><button type="submit">Submit (scanner will not submit it)</button></form>
<img src="http://127.0.0.1:9001/demo-image" alt="Local demo image">
<a href="/next">Another page</a>
<script>/* sourceMappingURL=app.js.map */</script>
</body></html>'''

@app.middleware("http")
async def localhost_only(request, call_next):
    client = request.client.host if request.client else ""
    host = request.headers.get("host", "").split(":",1)[0].strip("[]").lower()
    if client not in {"127.0.0.1", "::1", "localhost", "testclient"} or host not in {"127.0.0.1", "localhost", "testserver"}:
        return JSONResponse({"detail": "The demo lab is restricted to localhost."}, status_code=403)
    response = await call_next(request)
    # The missing headers and demo cookie are intentional and contain no real secrets.
    response.headers["Set-Cookie"] = "demo_session=demo-only-value; Path=/"
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response

@app.get("/", response_class=HTMLResponse)
def home():
    return PAGE

@app.get("/next", response_class=HTMLResponse)
def next_page():
    return "<!doctype html><html><body><h1>Demo page two</h1><p>Second local-only lab page.</p><a href='/'>Home</a></body></html>"

@app.get("/demo-image")
def demo_image():
    return {"demo": True}

@app.post("/submit")
def no_submit():
    return {"message": "The lab does not process credentials. KlyPen must never submit forms during scanning."}

if __name__ == "__main__":
    if os.getenv("KLYPEN_LAB_ENABLED", "false").lower() != "true":
        raise SystemExit("Set KLYPEN_LAB_ENABLED=true to start the local-only lab.")
    import uvicorn
    uvicorn.run("backend.lab.app:app", host="127.0.0.1", port=9001, reload=False)
