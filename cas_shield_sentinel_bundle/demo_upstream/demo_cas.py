from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

app = FastAPI()

@app.get("/health")
def health():
  return {"status": "ok"}

@app.get("/cas/login")
def login_get():
  return PlainTextResponse("CAS LOGIN PLACEHOLDER RESPONSE", status_code=200)

@app.post("/cas/login")
async def login_post(req: Request):
  # This demo upstream does not parse credentials; it just returns a generic response.
  return PlainTextResponse("CAS LOGIN POST RECEIVED", status_code=200)
