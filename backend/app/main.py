from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from .scanner import scan_zip

app=FastAPI(title="AegisFlow OMEGA API",version="3.0")
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])

@app.get("/api/health")
def health(): return {"status":"online","engine":"OMEGA Sentinel","version":"3.0","mode":"defensive"}

@app.post("/api/scan")
async def scan(file:UploadFile=File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(400,"Upload a .zip repository archive.")
    data=await file.read()
    if len(data)>50*1024*1024: raise HTTPException(413,"Archive exceeds 50 MB demo limit.")
    try: return scan_zip(data,file.filename)
    except ValueError as e: raise HTTPException(400,str(e))
    except Exception as e: raise HTTPException(500,f"Scan failed: {e}")
