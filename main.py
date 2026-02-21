from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re
import os

app = FastAPI(title="FraudGuard AI", description="A simple heuristic-based fraud detection API")

# ---------------------------------------------------------
# CORS CONFIGURATION
# ---------------------------------------------------------
# Setup CORS to allow cross-origin requests
# This is important so the frontend can easily communicate with the backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# DATA MODELS
# ---------------------------------------------------------
# We use Pydantic BaseModel to automatically validate incoming JSON data
class DetectionRequest(BaseModel):
    # Both SMS and Email will accept a single block of text to simplify the process
    text: str

# ---------------------------------------------------------
# HEURISTIC SCORING ALGORITHM
# ---------------------------------------------------------
def calculate_risk_score(text: str, message_type: str) -> dict:
    """
    Calculates a fraud risk score (out of 100) based on heuristic rules.
    This is an educational example of how a rule-based algorithm works.
    
    Rules:
    - Panic words add 20 points each.
    - Financial bait words add 20 points each.
    - Suspicious links add 40 points for SMS, but only 15 points for Email.
    """
    score = 0
    flags = [] # To keep track of exactly what triggered our rules
    
    # Convert text to lowercase for easier matching
    text_lower = text.lower()
    
    # Define our heuristic dictionaries (lists of suspicious keywords)
    panic_words = ["urgent", "suspended", "immediate", "action required", "warning", "verify", "alert"]
    financial_bait = ["winner", "lottery", "prize", "cash", "bank", "account", "money", "free", "gift"]
    
    # 1. Check for panic words
    # We create a list of all panic words that exist within the text
    found_panic = [word for word in panic_words if word in text_lower]
    if found_panic:
        # Give 20 points multiplied by the number of unique panic words found
        points = 20 * len(found_panic)
        score += points
        flags.append(f"Panic words detected (+{points} pts): {', '.join(found_panic)}")
        
    # 2. Check for financial bait
    found_bait = [word for word in financial_bait if word in text_lower]
    if found_bait:
        # Give 20 points multiplied by the number of unique financial bait words found
        points = 20 * len(found_bait)
        score += points
        flags.append(f"Financial bait detected (+{points} pts): {', '.join(found_bait)}")
        
    # 3. Check for web links using Regex (Regular Expressions)
    # This standard regex pattern checks for http/https links or standard www domains
    url_pattern = r"(https?://[^\s]+|www\.[^\s]+)"
    links_found = re.findall(url_pattern, text)
    
    if links_found:
        if message_type == "sms":
            # Links in SMS are highly suspicious (often used in "smishing" attacks)
            score += 40
            flags.append(f"Suspicious link found in SMS (+40 pts): {links_found[0]}")
        elif message_type == "email":
            # Links in emails are very common, so they represent lower risk natively
            score += 15
            flags.append(f"Link found in Email (+15 pts): {links_found[0]}")
            
    # Normalize the score to ensure it never exceeds 100
    if score > 100:
        score = 100
        
    # If the score remains 0, the text is considered completely clean
    if score == 0:
        flags.append("No suspicious indicators found.")
        
    # Categorize the numeric score into a readable Risk Level
    risk_level = "High" if score >= 60 else ("Medium" if score >= 30 else "Low")
        
    # Return a structured dictionary which FastAPI converts into JSON by default
    return {
        "score": score,
        "flags": flags,
        "risk_level": risk_level
    }

# ---------------------------------------------------------
# API ENDPOINTS
# ---------------------------------------------------------

@app.post("/detect-sms")
async def detect_sms(request: DetectionRequest):
    """
    Endpoint for scanning SMS messages.
    Expects JSON: {"text": "message content here"}
    """
    return calculate_risk_score(request.text, message_type="sms")

@app.post("/detect-email")
async def detect_email(request: DetectionRequest):
    """
    Endpoint for scanning Email messages.
    Expects JSON: {"text": "email content here"}
    """
    return calculate_risk_score(request.text, message_type="email")

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """
    Serves the frontend UI from index.html on the root URL location (/)
    Using HTMLResponse allows FastAPI to render HTML instead of JSON.
    """
    # Simply read the index.html file and return its textual content to the browser
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as file:
            return HTMLResponse(content=file.read())
            
    return HTMLResponse(content="<h1>Error: index.html not found</h1>", status_code=404)
