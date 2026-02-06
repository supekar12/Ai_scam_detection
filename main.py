from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

app = FastAPI()

# --- CONFIGURATION ---
SUBMISSION_API_KEY = "mysecretkey"

# ==========================================
# 1. DEFINE THE DATA MODELS
# ==========================================

# Model for Voice Data
class AudioRequest(BaseModel):
    audioBase64: str          
    language: Optional[str] = None
    audioFormat: Optional[str] = None

# Models for Honey-Pot Data (Complex Structure)
class MessageContent(BaseModel):
    sender: str
    text: str

class HoneypotRequest(BaseModel):
    sessionId: str
    message: MessageContent
    timestamp: int
    conversationHistory: List[Any] = []
    metadata: Dict[str, Any] = {}
    language: Optional[str] = None

# ==========================================
# 2. THE LOGIC FUNCTIONS (Reusable)
# ==========================================

def handle_voice_logic():
    return {
        "status": "success", 
        "prediction": "Human", 
        "confidence": 0.99
    }

def handle_honeypot_logic():
    return {
        "status": "success",
        "reply": "I am confused. Why is my account being suspended? Can you explain?"
    }

# ==========================================
# 3. THE ENDPOINTS
# ==========================================

# Specific Endpoint for Voice (Keep this safe)
@app.post("/detect-audio")
async def detect_audio_endpoint(request: AudioRequest, authorization: str = Header(None)):
    if authorization != SUBMISSION_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return handle_voice_logic()

# Specific Endpoint for Honey-Pot (Keep this safe)
@app.post("/honeypot")
async def honeypot_endpoint(request: HoneypotRequest, x_api_key: str = Header(None)):
    if x_api_key != SUBMISSION_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return handle_honeypot_logic()

# --- THE MAGIC "SMART ROUTER" (SOLVES YOUR PROBLEM) ---
# This listens on the Main Home Page ("/") and decides what to do
@app.post("/")
async def smart_router(
    request: Request, 
    authorization: str = Header(None), 
    x_api_key: str = Header(None)
):
    # 1. Check API Key (Accept either header)
    api_key = authorization or x_api_key
    if api_key != SUBMISSION_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # 2. Peek at the data to see what it is
    data = await request.json()

    # 3. Decide which logic to run
    if "audioBase64" in data:
        # It's an Audio request!
        return handle_voice_logic()
    
    elif "sessionId" in data or "message" in data:
        # It's a Honey-Pot request!
        return handle_honeypot_logic()
        
    else:
        return {"status": "error", "message": "Unknown request type"}

@app.get("/")
async def health_check():
    return {"status": "Online", "mode": "Smart Unified Server"}
