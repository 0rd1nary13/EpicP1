import base64
import hashlib
import secrets
import requests
import urllib3

from urllib.parse import urlencode
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

# Disable SSL warnings (only do this in a dev/test environment)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI()

# ------------------------
# 1) Session Middleware
# ------------------------
# The session cookie will store user data (code_verifier, state, access_token).
app.add_middleware(
    SessionMiddleware,
    secret_key=secrets.token_hex(32),  # keep this stable & secret in production
    session_cookie="epic_session",
    # If you have cross-site cookie issues, you might need:
    same_site="none",
    https_only=True,
)

# ------------------------
# 2) OAuth / FHIR Config
# ------------------------
CONFIG = {
    "client_id": "4bbe2c64-79c6-47fc-a322-23ee11cc5811",  # 请替换成你自己的client_id
    "redirect_uri": "https://f61d-107-132-35-127.ngrok-free.app/epic-sandbox/callback",  # 替换为你自己的回调地址
    "epic_base_url": "https://fhir.epic.com/interconnect-fhir-oauth",
    "scope": "openid fhirUser launch/patient Appointment.read",
    "fhir_api_base": "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4"
}

# ------------------------
# 3) PKCE Helpers
# ------------------------
def generate_code_verifier():
    """Generate a high-entropy code verifier."""
    token = secrets.token_urlsafe(64)
    return token[:128]  # 128-char limit recommended by RFC

def generate_code_challenge(verifier: str) -> str:
    """Transform the code_verifier into a code_challenge using SHA256 + base64-url."""
    sha256 = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(sha256).decode("utf-8").rstrip("=")

# ------------------------
# 4) Home Page
# ------------------------
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """
    Simple homepage that:
      - If not authenticated, shows a "Connect with Epic" button.
      - If authenticated, shows a basic Appointment search form.
    """
    access_token = request.session.get("access_token")
    if not access_token:
        # Not logged in
        return """
        <html>
          <body style="font-family: Arial; margin: 20px;">
            <h1>Welcome</h1>
            <p>You are not logged in with Epic.</p>
            <a href="/login" style="padding: 10px; background: #007BFF; color: #fff; text-decoration: none; border-radius: 5px;">
              Connect with Epic
            </a>
          </body>
        </html>
        """

    # If we have an access token, show the appointment search form
    return """
    <html>
      <body style="font-family: Arial; margin: 20px;">
        <h1>Epic Appointment Search</h1>
        <p>You are logged in! Enter Appointment search criteria:</p>
        <form action="/api/fhir/r4/Appointment" method="get">
          <label>Date: </label>
          <input type="date" name="date"><br><br>
          <label>Status: </label>
          <select name="status">
            <option value="">Any</option>
            <option value="booked">Booked</option>
            <option value="pending">Pending</option>
            <option value="arrived">Arrived</option>
            <option value="cancelled">Cancelled</option>
          </select><br><br>
          <button type="submit">Search Appointments</button>
        </form>
      </body>
    </html>
    """

# ------------------------
# 5) Login Endpoint
# ------------------------
@app.get("/login")
async def login(request: Request):
    """
    1) Generate code_verifier, code_challenge, and state
    2) Store them in the session
    3) Redirect to Epic's OAuth /authorize endpoint
    """
    code_verifier = generate_code_verifier()

    code_challenge = generate_code_challenge(code_verifier)
    state = secrets.token_hex(16)

    # Store in session so we can retrieve later in the callback
    request.session["code_verifier"] = code_verifier
    request.session["state"] = state

    # Build the /authorize URL
    auth_params = {
        "response_type": "code",
        "client_id": CONFIG["client_id"],
        "redirect_uri": CONFIG["redirect_uri"].strip(),
        "scope": CONFIG["scope"],
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "aud": CONFIG["fhir_api_base"]
    }

    auth_url = f"{CONFIG['epic_base_url']}/oauth2/authorize?{urlencode(auth_params)}"

    return RedirectResponse(url=auth_url)

# ------------------------
# 6) OAuth Callback
# ------------------------
@app.get("/epic-sandbox/callback")
async def epic_callback(request: Request, code: str = None, state: str = None):
    """
    Epic redirects here after successful user login.
    We verify 'state', then exchange 'code' and 'code_verifier' for an access token.
    """
    # Verify state
    stored_state = request.session.get("state")
    if not stored_state or stored_state != state:
        return {"error": "Invalid state parameter",
                "stored_state": stored_state,
                "received_state": state,
                "code": code}

    # Get code_verifier
    code_verifier = request.session.get("code_verifier")
    if not code_verifier:
        return {"error": "No code_verifier in session"}

    # Exchange code for token
    token_endpoint = f"{CONFIG['epic_base_url']}/oauth2/token"
    token_params = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": CONFIG["redirect_uri"],
        "client_id": CONFIG["client_id"],
        "code_verifier": code_verifier,
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(token_endpoint, data=token_params, headers=headers, verify=False)
    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {resp.text}")

    token_data = resp.json()
    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="No access_token in token response")

    # Store access_token in session
    request.session["access_token"] = access_token

    # Redirect to home
    return RedirectResponse(url="/")

# ------------------------
# 7) FHIR Appointment Search
# ------------------------
@app.get("/api/fhir/r4/Appointment")
async def search_appointments(request: Request, date: str = None, status: str = None):
    """
    Example endpoint that searches Epic FHIR Appointments
    using the stored 'access_token' from the session.
    """
    access_token = request.session.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated (no access_token in session).")

    # Build query params
    params = {}
    if date:
        params["date"] = date
    if status:
        params["status"] = status

    # Make the FHIR request
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/fhir+json"
    }
    url = f"{CONFIG['fhir_api_base']}/Appointment"
    response = requests.get(url, headers=headers, params=params, verify=False)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)

    return response.json()

# ------------------------
# 8) Entry Point
# ------------------------
if __name__ == "__main__":
    import uvicorn
    # 启动服务: uvicorn main:app --host 0.0.0.0 --port 3000
    uvicorn.run(app, host="0.0.0.0", port=3000)
