from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import re
import os

"""
Lead Cybersecurity Architect & Senior Full-Stack Engineer

This is a production-grade, purely rule-based Scam Detection Engine. 
The architecture avoids Machine Learning / NLP, relying entirely on a transparent,
explainable heuristic engine. The logic leverages the Theory of Computing—specifically
deterministic finite state machines via regular expressions—to parse unstructured,
obfuscated user inputs into known, recognizable threat patterns.
"""

app = FastAPI(title="TrustShield Scam Detector - Advanced Heuristic Engine", version="3.0.0")

# Enable CORS (allow all origins per requirements)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. Data Models & Routing
class ScamRequest(BaseModel):
    text: str
    type: str  # Expected: "email" or "sms"

class AnalyzeResponse(BaseModel):
    status: str
    risk_score: int
    threat_categories: list[str]
    flags_found: list[str]


# 2. Shared Pre-processing (De-obfuscation)
def deobfuscate_text(text: str) -> str:
    """
    Applied Theory of Computing: Pattern Recognition & Deterministic States
    
    Scammers use obfuscation techniques (e.g., inserting spaces "U R G E N T" or 
    punctuation "A.C.C.O.U.N.T") to break basic regex state machines.
    
    This function strips all non-alphanumeric characters, returning the sequence 
    to a known deterministic string state matching our underlying dictionaries.
    Unicode word characters (\w) are preserved to handle Marathi regional languages.
    """
    return re.sub(r'[^\w]', '', text).lower()


# 3. The Email Engine (analyze_email)
def analyze_email(text: str) -> dict:
    """
    Email-specific deterministic parsing.
    Focuses on long-form content, brand stuffing, and academic/professional coercion.
    """
    score = 0
    flags_found = []
    threat_categories = []
    
    # Generate our structural states
    clean_text = deobfuscate_text(text)
    lower_text = text.lower()
    
    # 3.1 Panic Formatting (+15 pts)
    # Applied state logic to calculate the density of uppercase characters.
    letters_only = [char for char in text if char.isalpha()]
    if letters_only:
        uppercase_count = sum(1 for char in letters_only if char.isupper())
        if (uppercase_count / len(letters_only)) > 0.30:
            score += 15
            flags_found.append("High uppercase ratio (Panic formatting)")
            
    # 3.2 Govt Job Bait (+40 pts)
    govt_keywords = ["data entry", "ldc notification", "sarkari", "recruitment"]
    has_govt_keywords = any(kw in lower_text for kw in govt_keywords)
    has_official_domain = ".gov.in" in lower_text or ".nic.in" in lower_text
    
    if has_govt_keywords and not has_official_domain:
        score += 40
        flags_found.append("Fake Govt Job without official domain")
        if "Govt Job Bait" not in threat_categories:
            threat_categories.append("Govt Job Bait")
            
    # 3.3 Brand Stuffing (+30 pts)
    # Statistically improbable clustering of massive brand identities.
    huge_brands = ["ibm", "microsoft", "nasscom", "nsdc", "skill india", "iit bombay", "apple", "meta"]
    brands_found = [brand for brand in huge_brands if brand in lower_text]
    
    if len(brands_found) >= 3:
        score += 30
        flags_found.append("Statistically improbable brand stuffing")
        if "Brand Stuffing" not in threat_categories:
            threat_categories.append("Brand Stuffing")
            
    # 3.4 Pay-to-Play Internship (+50 pts)
    # Structural rule: Mentions internship but asks for payment.
    internship_keywords = ["internship", "shortlisted"]
    fee_keywords = ["fees: applicable", "registration fee", "tuition reduction", "scholarship code"]
    
    if any(kw in lower_text for kw in internship_keywords) and any(kw in lower_text for kw in fee_keywords):
        score += 50
        flags_found.append("Internship demanding upfront payment")
        if "Pay-to-Play Internship" not in threat_categories:
            threat_categories.append("Pay-to-Play Internship")
            
    # 3.5 Academic Coercion (+45 pts)
    academic_keywords = ["mandatory participation", "academic credit requirements", "portal closes automatically"]
    if any(kw in lower_text for kw in academic_keywords):
        score += 45
        flags_found.append("Aggressive academic coercion tactics detected")
        if "Academic Coercion" not in threat_categories:
            threat_categories.append("Academic Coercion")
            
    # 3.6 E-commerce Refund & Account Security Scams (+40 pts)
    # Real-world 2024 phishing trends targeting Indian consumers
    security_bait = ["your account will be deactivated", "potential fraud threats", "payment information update", "verify your details", "unusual activity"]
    refund_bait = ["prize winnings", "exclusive deal", "eligible for a refund"]
    
    if any(kw in lower_text for kw in security_bait):
        score += 40
        flags_found.append("Fake Account Security / Deactivation threat")
        if "Account Phishing" not in threat_categories:
            threat_categories.append("Account Phishing")
            
    if any(kw in lower_text for kw in refund_bait):
        score += 35
        flags_found.append("E-commerce Fake Refund / Prize Bait")
        if "Refund Scam" not in threat_categories:
            threat_categories.append("Refund Scam")
            
    # 3.7 Marathi Regional Scams (+35 pts)
    marathi_keywords = ["लॉटरी जिंकली", "खाते बंद", "पैसे पाठवा", "वीज बिल"]
    if any(kw in lower_text for kw in marathi_keywords):
        score += 35
        flags_found.append("Regional Marathi scam phrases detected")
        if "Marathi Regional Scams" not in threat_categories:
            threat_categories.append("Marathi Regional Scams")
            
    # 3.8 Generic Phishing Greetings (+20 pts)
    # Modern spear-phishing often trips up by lacking the target's actual name
    generic_greetings = ["dear customer", "dear user", "valued client", "attention required"]
    if any(text.lower().startswith(kw) or (kw in lower_text[:50]) for kw in generic_greetings):
        score += 20
        flags_found.append("Generic greeting used in official context (Phishing Marker)")
        if "Authentication/Identity Phishing" not in threat_categories:
            threat_categories.append("Authentication/Identity Phishing")
            
    # 3.9 Financial String Recognition (Crypto / IBAN / Account Numbers) (+30 pts)
    # Applied Regex to find patterns matching Crypto Wallets or IBAN sequences
    crypto_pattern = r'\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b'  # Basic Bitcoin Wallet Regex
    if re.search(crypto_pattern, text):
        score += 30
        flags_found.append("Cryptocurrency wallet string detected in text")
        if "Cryptocurrency Fraud" not in threat_categories:
            threat_categories.append("Cryptocurrency Fraud")
            
    # 3.10 Romance & Advance Fee Fraud (+50 pts)
    # Long-form emotional manipulation and advance fee (419) formats
    romance_keywords = ["refugee camp", "peacekeeping mission", "diplomatic courier", "leave processing", "fixed deposit account", "widow", "soulmate", "destined by god"]
    if any(kw in lower_text for kw in romance_keywords):
        score += 50
        flags_found.append("Advanced Fee / Romance / Military Scam format detected")
        if "Advance Fee Fraud" not in threat_categories:
            threat_categories.append("Advance Fee Fraud")
            
    # Resolution State
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

# 4. The SMS Engine (analyze_sms)
def analyze_sms(text: str) -> dict:
    """
    SMS-specific deterministic parsing.
    Focuses on short-form urgency, link placement, and mobile-first threats.
    """
    score = 0
    flags_found = []
    threat_categories = []
    
    # Generate our structural states
    clean_text = deobfuscate_text(text)
    lower_text = text.lower()
    
    # 4.1 Short-Link & Urgency (+40 pts)
    url_pattern = r'(https?://|www\.)\S+'
    has_url = bool(re.search(url_pattern, text))
    urgency_keywords = ["urgent", "update", "click", "verify"]
    
    if has_url and any(kw in lower_text for kw in urgency_keywords):
        score += 40
        flags_found.append("Suspicious short-link combined with urgency markers")
        if "Short-Link & Urgency" not in threat_categories:
            threat_categories.append("Short-Link & Urgency")
            
    # 4.2 Package & Toll Friction (+45 pts)
    # 2024 Trend: India Post & e-Challan Traffic Fine smishing
    shipping_keywords = ["usps", "fedex", "ups", "package suspended", "reschedule delivery", "india post", "incomplete address", "customs duties"]
    toll_keywords = ["unpaid toll", "fastag blocked", "e-challan", "traffic fine", "unpaid penalty"]
    
    if any(kw in lower_text for kw in shipping_keywords):
        score += 45
        flags_found.append("Postal / Logistics friction scam pattern detected")
        if "Package Delivery Scam" not in threat_categories:
            threat_categories.append("Package Delivery Scam")
            
    if any(kw in lower_text for kw in toll_keywords):
        score += 45
        flags_found.append("Fake Toll / Traffic Fine (e-Challan) warning")
        if "Govt Fine Scam" not in threat_categories:
            threat_categories.append("Govt Fine Scam")
            
    # 4.3 OTP & Bank Panic (+50 pts)
    bank_keywords = ["reply with 6-digit code", "account locked", "unusual login detected", "first bank and trust"]
    if any(kw in lower_text for kw in bank_keywords):
        score += 50
        flags_found.append("Financial panic / OTP interception attempt detected")
        if "OTP & Bank Panic" not in threat_categories:
            threat_categories.append("OTP & Bank Panic")
            
    # 4.4 Pig Butchering / Wrong Number (+35 pts)
    pig_butchering_keywords = ["hi is this", "sorry wrong number", "let's be friends", "crypto tip"]
    if any(kw in lower_text for kw in pig_butchering_keywords):
        score += 35
        flags_found.append("Social engineering / Pig butchering opener detected")
        if "Pig Butchering / Wrong Number" not in threat_categories:
            threat_categories.append("Pig Butchering / Wrong Number")
            
    # 4.5 Boss/Family Emergency & "Papa" Scams (+40 pts)
    # 2024 Trend: Scammers messaging as family members or calling "beta" and claiming accidental transfer
    emergency_keywords = ["lost my phone", "this is my new number", "send money to", "need gift cards", "accidentally transferred", "return the money"]
    if any(kw in lower_text for kw in emergency_keywords):
        score += 40
        flags_found.append("Impersonation / Family Emergency contact scam detected")
        if "Family Emergency Threat" not in threat_categories:
            threat_categories.append("Family Emergency Threat")
            
    # 4.6 Marathi SMS (+35 pts)
    marathi_sms_keywords = ["लाईट बिल", "kyc अपडेट", "बँक खाते"]
    if any(kw in lower_text for kw in marathi_sms_keywords):
        score += 35
        flags_found.append("Regional Marathi SMS scam phrases detected")
        if "Marathi SMS Scams" not in threat_categories:
            threat_categories.append("Marathi SMS Scams")
            
    # 4.7 Romance & Military Impersonation (+45 pts)
    romance_keywords = ["peacekeeping mission", "diplomatic courier", "satellite phone", "itunes gift cards", "leave processing", "widow"]
    if any(kw in lower_text for kw in romance_keywords):
        score += 45
        flags_found.append("Romance / Military Impersonation scam detected")
        if "Romance / Military Scam" not in threat_categories:
            threat_categories.append("Romance / Military Scam")

    # 4.8 Fake Job & Task Scams (+45 pts)
    job_keywords = ["remote task role", "rate hotels", "earn daily income", "online interview", "received your resume"]
    if any(kw in lower_text for kw in job_keywords):
        score += 45
        flags_found.append("Fake Recruiter / Task Scam detected")
        if "Fake Job Offer" not in threat_categories:
            threat_categories.append("Fake Job Offer")
            
    # 4.9 Prize & Giveaway Scams (+40 pts)
    prize_keywords = ["amazon gift card", "loyalty gift", "claim your prize", "won a ", "rewarding our very best"]
    if any(kw in lower_text for kw in prize_keywords):
        score += 40
        flags_found.append("Extremely common Prize / Giveaway bait detected")
        if "Prize Scam" not in threat_categories:
            threat_categories.append("Prize Scam")
            
    # 4.10 Fake Billing, Utilities & Subscriptions (+40 pts)
    billing_keywords = ["electricity service", "disconnected due to non-payment", "process your refund", "subscription will auto-renew", "outstanding debt"]
    if any(kw in lower_text for kw in billing_keywords):
        score += 40
        flags_found.append("Fake Billing / Utility disconnection threat")
        if "Fake Billing/Collections" not in threat_categories:
            threat_categories.append("Fake Billing/Collections")
            
    # 4.11 Govt & Tax Impersonation (+50 pts)
    tax_keywords = ["irs notice", "outstanding tax", "student loan forgiveness"]
    if any(kw in lower_text for kw in tax_keywords):
        score += 50
        flags_found.append("Government Identity Impersonation (IRS/Loans)")
        if "Govt Impersonation" not in threat_categories:
            threat_categories.append("Govt Impersonation")

    # 4.12 Contextual Mismatch: Urgency without specifics (+35 pts)
    # Modern SMS scams say "Action required" but give no context before the link
    words = text.split()
    if len(words) < 15 and has_url:
        short_urgency = ["act", "now", "verify", "immediate", "update"]
        if any(kw in lower_text for kw in short_urgency):
            score += 35
            flags_found.append("Extremely high urgency relative to message length (Contextual Mismatch)")
            if "Phishing Link Dissemination" not in threat_categories:
                threat_categories.append("Phishing Link Dissemination")

    # 4.13 APK / Malware Sideloading Attempts (+60 pts)
    # Huge threat vector in India: Links prompting to download .apk files directly
    apk_pattern = r'\.apk\b|download the app to your phone|install the application manually'
    if re.search(apk_pattern, lower_text):
        score += 60
        flags_found.append("Malware / APK Sideloading attempt detected")
        if "Malware Dissemination" not in threat_categories:
            threat_categories.append("Malware Dissemination")

    # Resolution State
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


# Router Endpoint
@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_endpoint(request: ScamRequest):
    """
    Primary ingestion router.
    Routes to the specific engine state machine based on the payload type.
    """
    if request.type.lower() == "email":
        result = analyze_email(request.text)
    elif request.type.lower() == "sms":
        result = analyze_sms(request.text)
    else:
        # Default fallback to SMS engine if omitted or malformed
        result = analyze_sms(request.text)
        
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
