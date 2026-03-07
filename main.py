from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import re
import math
import os

"""
Lead Cybersecurity Architect Instructions:
This is a robust, production-grade Rule-Based Scam Detection System.
The architecture avoids Machine Learning / NLP, relying entirely on a transparent,
explainable heuristic engine. This allows security analysts to understand exactly
why a message was flagged, which is crucial for enterprise-grade compliance.
"""

app = FastAPI(title="TrustShield Scam Detector", version="2.0.0")

# Enable CORS (allow all origins per requirements)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SMSRequest(BaseModel):
    text: str

class EmailRequest(BaseModel):
    sender: str
    subject: str
    body: str

class AnalyzeResponse(BaseModel):
    status: str
    risk_score: int
    threat_categories: list[str]
    flags_found: list[str]

# D. Weighted Keyword Dictionaries
# Organized by threat vectors. Keywords are defined with spaces for human readability.
SCAM_CATEGORIES = {
    "Job & Education Scams": {
        "points": 35,
        "keywords": [
            "security deposit", "registration fee required", "guaranteed placement", 
            "no interview needed", "pay for training"
        ]
    },
    "Digital Arrest & Extortion": {
        "points": 45,
        "keywords": [
            "cbi investigation", "customs department", "arrest warrant", 
            "aadhaar misuse", "pay to avoid arrest", "illegal parcel"
        ]
    },
    "Financial & Lottery Scams": {
        "points": 30,
        "keywords": [
            "claim your prize", "lucky draw winner", "kyc suspended", 
            "jio free recharge", "account blocked", "immediate action required"
        ]
    },
    "Regional Marathi Scams": {
        "points": 35,
        "keywords": [
            "लॉटरी जिंकली", "खाते बंद", "पैसे पाठवा", "वीज बिल"
        ]
    }
}

def analyze_fraud_risk(text: str, is_email: bool = False, sender: str = "") -> dict:
    """
    Core Heuristic Engine: Analyzes text structurally and contextually.
    Calculates a risk score capped at 100 based on rigorous rules.
    """
    score = 0
    flags_found = []
    threat_categories = []
    
    # --- A. Pre-processing & De-obfuscation ---
    cleaned_text = re.sub(r'[^\w]', '', text).lower()
    
    # --- B. Structural & Formatting Analysis ---
    # B1. The Shouting Rule (Panic formatting)
    letters_only = [char for char in text if char.isalpha()]
    if len(letters_only) > 0:
        uppercase_count = sum(1 for char in letters_only if char.isupper())
        if (uppercase_count / len(letters_only)) > 0.30:
            score += 15
            flags_found.append("High uppercase ratio (Panic formatting)")
            
    # B2. Desperation Marks
    if "!!!" in text or "???" in text:
        score += 10
        flags_found.append("Excessive urgency punctuation")
        
    # --- C. Advanced Regex Checks ---
    # C1. Suspicious Sender Spoofing
    free_email_pattern = r'@(?:gmail\.com|yahoo\.com|hotmail\.com|outlook\.com|live\.com)'
    
    # If it's an email check the explicit sender field
    sender_to_check = sender.lower() if is_email and sender else text.lower()
    has_free_email = bool(re.search(free_email_pattern, sender_to_check))
    
    bank_keywords = ["sbi", "hdfc", "axis", "icici"]
    has_bank = any(bank in text.lower() for bank in bank_keywords)
    
    if has_free_email and has_bank:
        score += 45
        flags_found.append("Free email claiming to be a bank")
        
    # C2. Phishing Links
    url_pattern = r'(https?://|www\.)\S+'
    has_url = bool(re.search(url_pattern, text))
    
    urgency_keywords = ["immediate", "suspend", "verify"]
    has_url_urgency = any(kw.replace(" ", "") in cleaned_text for kw in urgency_keywords)
    
    if has_url and has_url_urgency:
        score += 20
        flags_found.append("Suspicious link with urgent call-to-action")
        
    # --- D. Weighted Keyword Dictionaries Analysis ---
    for category_name, category_data in SCAM_CATEGORIES.items():
        points = category_data["points"]
        for keyword in category_data["keywords"]:
            clean_keyword = re.sub(r'[^\w]', '', keyword).lower()
            if clean_keyword in cleaned_text:
                score += points
                flags_found.append(f"Matched keyword trigger: '{keyword}'")
                if category_name not in threat_categories:
                    threat_categories.append(category_name)
                    
    # --- Modifiers based on source ---
    # Emails are slightly lower risk inherently unless specific flags are hit,
    # because they support richer HTML formatting that might trigger false positives.
    if is_email:
        score = int(score * 0.85)

    # --- E. Final State Resolution ---
    score = min(score, 100)
    
    if score >= 60:
        status = "CRITICAL SCAM"
    elif score >= 30:
        status = "SUSPICIOUS"
    else:
        status = "SAFE"
        
    return {
        "status": status,
        "risk_score": score,
        "threat_categories": threat_categories,
        "flags_found": flags_found
    }

@app.post("/detect-sms", response_model=AnalyzeResponse)
def detect_sms_endpoint(request: SMSRequest):
    """
    SMS Ingestion endpoint. Accepts JSON payload, pipes it through
    the heuristic engine, and returns structured threat intelligence.
    """
    result = analyze_fraud_risk(text=request.text, is_email=False)
    return AnalyzeResponse(**result)

@app.post("/detect-email", response_model=AnalyzeResponse)
def detect_email_endpoint(request: EmailRequest):
    """
    Email Ingestion endpoint. Accepts explicit sender/subject/body.
    Combines text for core heuristic analysis, applying email-specific logic.
    """
    combined_text = f"Subject: {request.subject}\n\n{request.body}"
    result = analyze_fraud_risk(text=combined_text, is_email=True, sender=request.sender)
    return AnalyzeResponse(**result)

@app.get("/", response_class=HTMLResponse)
def read_root():
    """
    Frontend routing logic. 
    Serves the premium dashboard directly from root.
    """
    html_path = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Error: index.html missing from the server root.</h1>"
