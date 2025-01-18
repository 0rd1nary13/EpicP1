import base64
import hashlib
import secrets
import requests
import urllib3
from typing import Optional
from urllib.parse import urlencode
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response
import json
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

# Disable SSL warnings in dev/test
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI()

# Update CORS middleware to be more permissive for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Update session middleware configuration
app.add_middleware(
    SessionMiddleware,
    secret_key="your-super-secret-key",  # Use a strong secret key
    session_cookie="epic_session",
    max_age=3600,
    same_site="none",  # Important for cross-domain requests
    https_only=True,
)

# Add in-memory storage for PKCE values
pkce_storage = {}

CONFIG = {
    "client_id": "4bbe2c64-79c6-47fc-a322-23ee11cc5811",
    "redirect_uri": "https://f61d-107-132-35-127.ngrok-free.app/epic-sandbox/callback",
    "epic_base_url": "https://fhir.epic.com/interconnect-fhir-oauth",
    "scope": "openid fhirUser launch/patient Appointment.read",
    "fhir_api_base": "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4"
}


def generate_code_verifier():
    token = secrets.token_urlsafe(64)
    return token[:128]


def generate_code_challenge(verifier):
    sha256 = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(sha256).decode('utf-8').rstrip('=')


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    access_token = request.session.get("access_token")
    if not access_token:
        return """
        <html>
          <body style="font-family: Arial; margin: 20px;">
            <h1>Welcome</h1>
            <p>You are not logged in with Epic.</p>
            <a href="/epic-sandbox/callback" style="padding: 10px 15px; background: #007BFF; color: #fff; text-decoration: none; border-radius: 5px;">
              Connect with Epic
            </a>
          </body>
        </html>
        """

    return """
    <html>
      <body style="font-family: Arial; margin: 20px;">
        <h1>Epic Appointment Search</h1>
        <p>You are logged in! Enter search criteria:</p>
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


@app.get("/epic-sandbox/callback")
async def auth_handler(
        request: Request,
        code: Optional[str] = None,
        state: Optional[str] = None,
        error: Optional[str] = None
):
    """Combined login and callback handler with improved session handling"""

    # If no code present, this is the initial login request
    if not code:
        # Generate new PKCE values
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)
        state = secrets.token_hex(16)

        # Store PKCE values in both session and backup storage
        pkce_storage[state] = {
            "code_verifier": code_verifier,
            "timestamp": datetime.now().timestamp()
        }

        # Set session values
        request.session["state"] = state
        request.session["code_verifier"] = code_verifier

        # Generate authorization URL
        auth_params = {
            "response_type": "code",
            "client_id": CONFIG["client_id"],
            "redirect_uri": CONFIG["redirect_uri"],
            "scope": CONFIG["scope"],
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "aud": CONFIG["fhir_api_base"]
        }

        auth_url = f"{CONFIG['epic_base_url']}/oauth2/authorize?{urlencode(auth_params)}"

        # Create response with session cookie
        response = RedirectResponse(url=auth_url)
        response.set_cookie(
            key="epic_state",
            value=state,
            httponly=True,
            secure=True,
            samesite="none",
            max_age=3600
        )
        return response

    # This is the callback with authorization code
    if error:
        raise HTTPException(status_code=400, detail=f"Authorization error: {error}")

    # Try to get state from multiple sources
    stored_state = (
            request.session.get("state") or
            request.cookies.get("epic_state") or
            state
    )

    # Get code_verifier from multiple sources
    code_verifier = (
            request.session.get("code_verifier") or
            (pkce_storage.get(stored_state, {}).get("code_verifier") if stored_state else None)
    )

    if not code_verifier:
        raise HTTPException(status_code=400, detail="Missing code verifier. Please try logging in again.")

    try:
        # Exchange code for token
        token_params = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": CONFIG["redirect_uri"],
            "client_id": CONFIG["client_id"],
            "code_verifier": code_verifier
        }

        token_response = requests.post(
            f"{CONFIG['epic_base_url']}/oauth2/token",
            data=token_params,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify=False
        )

        if token_response.status_code != 200:
            raise Exception(f"Token exchange failed: {token_response.text}")

        token_data = token_response.json()

        # Create response with token
        response = RedirectResponse(url="/")

        # Store access token in both session and cookie
        request.session["access_token"] = token_data.get("access_token")
        response.set_cookie(
            key="epic_token",
            value=token_data.get("access_token"),
            httponly=True,
            secure=True,
            samesite="none",
            max_age=3600
        )

        # Clean up
        if stored_state in pkce_storage:
            del pkce_storage[stored_state]

        return response

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/fhir/r4/Appointment")
async def search_appointments(
        request: Request,
        date: Optional[str] = None,
        status: Optional[str] = None
):
    """Search appointments with improved token handling"""
    # Try to get access token from multiple sources
    access_token = (
            request.session.get("access_token") or
            request.cookies.get("access_token") or
            request.headers.get("Authorization", "").replace("Bearer ", "")
    )

    if not access_token:
        return JSONResponse(
            status_code=401,
            content={"status": "error", "message": "Not authenticated"}
        )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/fhir+json"
    }

    params = {}
    if date:
        params["date"] = date
    if status:
        params["status"] = status

    try:
        response = requests.get(
            f"{CONFIG['fhir_api_base']}/Appointment",
            params=params,
            headers=headers,
            verify=False
        )

        if response.status_code == 200:
            return JSONResponse(content=response.json())
        else:
            return JSONResponse(
                status_code=response.status_code,
                content={"status": "error", "message": response.text}
            )

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": str(e)}
        )


# Update the cleanup function to clean pkce_storage instead of temp_storage
@app.on_event("startup")
async def cleanup_storage():
    """Clean up expired PKCE values"""
    current_time = datetime.now().timestamp()
    expired_states = [
        state for state, data in pkce_storage.items()
        if current_time - data.get("timestamp", 0) > 3600
    ]
    for state in expired_states:
        del pkce_storage[state]


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=3000)
