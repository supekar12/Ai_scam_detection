import urllib.request
import json

BASE_URL = "http://127.0.0.1:8000"

def test_endpoint(endpoint, data):
    url = f"{BASE_URL}{endpoint}"
    headers = {'Content-Type': 'application/json'}
    req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers=headers, method='POST')
    
    try:
        with urllib.request.urlopen(req) as response:
            print(f"Testing {endpoint}...")
            print(f"Status: {response.status}")
            print(f"Response: {response.read().decode('utf-8')}")
            print("-" * 20)
    except Exception as e:
        print(f"Error testing {endpoint}: {e}")

# Test SMS
test_endpoint("/detect-sms", {"text": "URGENT: Verify your account now."})

# Test Email
test_endpoint("/detect-email", {
    "sender": "admin@free-money.com",
    "subject": "You won!",
    "body": "Click here."
})

# Test AI Text
test_endpoint("/detect-ai-text", {"text": "This is a simple sentence."})
