from fastapi import FastAPI, Header, HTTPException, Depends, status, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Union
import logging

# Shared Configuration
SUBMISSION_API_KEY = "mysecretkey"

app = FastAPI(title="Unified Hackathon API")

# Debugging 422 Errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logging.error(f"Validation error: {exc}")
    body = await request.body()
    logging.error(f"Request body: {body.decode()}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors(), "body": body.decode()},
    )

@app.get("/")
def read_root():
    return {
        "message": "Unified Hackathon API is running.",
        "endpoints": ["/detect-audio", "/honeypot"],
        "documentation": "/docs"
    }

# --- Problem 1: AI Voice Detection ---

class VoiceDetectionInput(BaseModel):
    model_config = {"populate_by_name": True}
    audiobase64: str = Field(..., alias="audioBase64")
    language: Optional[str] = None
    audioformat: Optional[str] = Field(None, alias="audioFormat")

class VoiceDetectionOutput(BaseModel):
    status: str
    prediction: str
    confidence: float

# Dependency for Endpoint 1 Auth
def verify_voice_auth(
    authorization: str = Header(None),
    x_api_key: str = Header(None)
):
    # 1. Try Authorization header
    if authorization:
        authorization = authorization.strip()
        if authorization.lower().startswith("bearer"):
            parts = authorization.split()
            if len(parts) == 2 and parts[0].lower() == "bearer":
                authorization = parts[1]
        
        if authorization == SUBMISSION_API_KEY:
            return authorization

    # 2. Try x-api-key header
    if x_api_key and x_api_key == SUBMISSION_API_KEY:
        return x_api_key

    # 3. If both fail
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid Authorization header or x-api-key"
    )

@app.post("/detect-audio", response_model=VoiceDetectionOutput)
async def detect_audio(
    data: VoiceDetectionInput, 
    api_key: str = Depends(verify_voice_auth)
):
    # Mock logic
    return {
        "status": "success",
        "prediction": "human",
        "confidence": 0.99
    }

# --- Problem 2: Agentic Honey-pot ---

class HoneypotMessage(BaseModel):
    sender: str
    text: str
    timestamp: int

class HoneypotInput(BaseModel):
    message: Union[HoneypotMessage, str]
    sessionId: Optional[str] = None
    conversationHistory: Optional[List[dict]] = None
    metadata: Optional[Dict[str, str]] = None

class ExtractedIntelligence(BaseModel):
    upi_ids: List[str]
    bank_accounts: List[str]
    phishing_links: List[str]

class HoneypotOutput(BaseModel):
    classification: str
    generated_reply: str
    extracted_intelligence: ExtractedIntelligence
    status: str

# Dependency for Endpoint 2 Auth
def verify_honeypot_auth(x_api_key: str = Header(None)):
    if x_api_key is None or x_api_key != SUBMISSION_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid x-api-key header"
        )
    return x_api_key

@app.post("/honeypot", response_model=HoneypotOutput)
async def honeypot(
    data: HoneypotInput,
    api_key: str = Depends(verify_honeypot_auth)
):
    # Mock logic
    return {
        "classification": "scam",
        "generated_reply": "I am confused, please help.",
        "extracted_intelligence": {
            "upi_ids": [],
            "bank_accounts": [],
            "phishing_links": []
        },
        "status": "success"
    }
