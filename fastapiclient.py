import base64
import hashlib
import json
import secrets
from urllib.parse import urlencode
import requests
import urllib3
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from starlette.middleware.sessions import SessionMiddleware

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=secrets.token_hex(32),
    session_cookie="epic_session"
)

CONFIG = {
    'client_id': '4bbe2c64-79c6-47fc-a322-23ee11cc5811',
    'redirect_uri': 'https://7b26-137-110-45-62.ngrok-free.app/epic-sandbox/callback',
    'epic_base_url': 'https://fhir.epic.com/interconnect-fhir-oauth',
    'scope': 'openid fhirUser launch/patient Appointment.read',
    'fhir_api_base': 'https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4'
}

def generate_code_verifier():
    token = secrets.token_urlsafe(64)
    return token[:128]

def generate_code_challenge(verifier):
    sha256 = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(sha256).decode('utf-8').rstrip('=')

@app.get("/", response_class=HTMLResponse)
async def manual_token_page(request: Request):
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    state = secrets.token_hex(16)

    auth_params = {
        'response_type': 'code',
        'client_id': CONFIG['client_id'],
        'redirect_uri': CONFIG['redirect_uri'].strip(),
        'scope': CONFIG['scope'],
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'aud': CONFIG['fhir_api_base']
    }

    auth_url = f"{CONFIG['epic_base_url']}/oauth2/authorize?{urlencode(auth_params)}"

    return f"""
    <html>
        <head>
            <title>Epic Appointment API Test</title>
            <style>
                body {{ padding: 20px; font-family: Arial, sans-serif; }}
                textarea {{ width: 100%; height: 150px; margin: 10px 0; }}
                button {{ padding: 10px 20px; margin: 5px; }}
                input, select {{ padding: 8px; margin: 5px; }}
                pre {{ margin-top: 20px; white-space: pre-wrap; background: #f5f5f5; padding: 10px; }}
                .section {{ margin-top: 30px; padding-top: 20px; }}
                .error {{ color: #721c24; background-color: #f8d7da; padding: 10px; margin: 10px 0; border-radius: 4px; }}
                .success {{ color: #155724; background-color: #d4edda; padding: 10px; margin: 10px 0; border-radius: 4px; }}
                .tabs {{ margin-bottom: 20px; }}
                .tab-content {{ padding: 20px; border: 1px solid #ddd; border-radius: 4px; }}
                .search-form {{ display: grid; gap: 15px; max-width: 600px; }}
                .form-group {{ display: grid; grid-template-columns: 150px 1fr; align-items: center; gap: 10px; }}
            </style>
            <script>
                const CODE_VERIFIER = '{code_verifier}';
                const AUTH_URL = '{auth_url}';
                const EXAMPLE_PATIENT_ID = 'eNO3wqOfAltfnWMfWBQ1WmQ3';

                function startAuth() {{
                    window.open(AUTH_URL, '_blank');
                }}

                async function submitURL() {{
                    const url = document.getElementById('urlInput').value;
                    const response = await fetch('/process-callback-url', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ url, code_verifier: CODE_VERIFIER }})
                    }});
                    const data = await response.json();
                    document.getElementById('tokenResult').textContent = JSON.stringify(data, null, 2);
                }}

                async function searchAppointments() {{
                    const params = new URLSearchParams();
                    const date = document.getElementById('searchDate').value;
                    const patient = document.getElementById('searchPatient').value;
                    const status = document.getElementById('searchStatus').value;
                    const category = document.getElementById('searchCategory').value;

                    if (date) params.append('date', date);
                    if (patient) params.append('patient', patient);
                    if (status) params.append('status', status);
                    if (category) params.append('service-category', category);

                    const response = await fetch(`/api/fhir/r4/Appointment?${{params.toString()}}`);
                    const data = await response.json();
                    document.getElementById('appointmentResults').textContent = JSON.stringify(data, null, 2);
                }}

                function useExamplePatientId() {{
                    document.getElementById('searchPatient').value = EXAMPLE_PATIENT_ID;
                }}
            </script>
        </head>
        <body>
            <h1>Epic Appointment API Test</h1>

            <div class="section">
                <h3>Step 1: Start Authorization</h3>
                <button onclick="startAuth()">Start Authorization</button>
                <div class="debug-info">
                    <pre>Code Verifier: {code_verifier}</pre>
                    <pre>Code Challenge: {code_challenge}</pre>
                    <pre>State: {state}</pre>
                </div>
            </div>

            <div class="section">
                <h3>Step 2: Enter Callback URL</h3>
                <textarea id="urlInput" placeholder="Paste the callback URL here"></textarea>
                <button onclick="submitURL()">Process URL</button>
                <pre id="tokenResult"></pre>
            </div>

            <div class="section">
                <h3>Step 3: Search Appointments</h3>
                <div class="search-form">
                    <div class="form-group">
                        <label>Date:</label>
                        <input type="date" id="searchDate">
                    </div>
                    <div class="form-group">
                        <label>Patient ID:</label>
                        <input type="text" id="searchPatient" placeholder="Patient reference">
                        <button onclick="useExamplePatientId()">Use Example ID</button>
                    </div>
                    <div class="form-group">
                        <label>Status:</label>
                        <select id="searchStatus">
                            <option value="">Any</option>
                            <option value="booked">Booked</option>
                            <option value="pending">Pending</option>
                            <option value="arrived">Arrived</option>
                            <option value="cancelled">Cancelled</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Service Category:</label>
                        <input type="text" id="searchCategory" value="appointment">
                    </div>
                    <button onclick="searchAppointments()">Search Appointments</button>
                </div>
                <pre id="appointmentResults"></pre>
            </div>
        </body>
    </html>
    """

@app.post("/process-callback-url")
async def process_callback_url(request: Request):
    try:
        data = await request.json()
        url = data.get('url')
        code_verifier = data.get('code_verifier')

        from urllib.parse import urlparse, parse_qs
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        code = params.get('code', [None])[0]

        token_params = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': CONFIG['redirect_uri'].strip(),
            'client_id': CONFIG['client_id'],
            'code_verifier': code_verifier
        }

        token_response = requests.post(
            f"{CONFIG['epic_base_url']}/oauth2/token",
            data=token_params,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            verify=False
        )

        if token_response.status_code == 200:
            token_data = token_response.json()
            request.session['access_token'] = token_data.get('access_token')
            return {"status": "success", "token_data": token_data}
        return {"status": "error", "message": f"Failed to get access token: {token_response.text}"}

    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/fhir/r4/Appointment")
async def search_appointments(
    request: Request,
    date: str = None,
    identifier: str = None,
    patient: str = None,
    status: str = None,
    service_category: str = None
):
    try:
        access_token = request.session.get('access_token')
        if not access_token:
            return {
                "status": "error",
                "error_code": "4118",
                "message": "User not authorized: No access token found"
            }

        params = {}
        if date: params['date'] = date
        if identifier: params['identifier'] = identifier
        if patient: params['patient'] = patient
        if status: params['status'] = status
        if service_category: params['service-category'] = service_category

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/fhir+json'
        }

        response = requests.get(
            f"{CONFIG['fhir_api_base']}/Appointment",
            params=params,
            headers=headers,
            verify=False
        )

        if response.status_code == 200:
            return {"status": "success", "data": response.json()}
        else:
            try:
                error_data = response.json()
                if "issue" in error_data:
                    issue = error_data["issue"][0]
                    return {
                        "status": "error",
                        "error_code": issue.get("code", str(response.status_code)),
                        "message": issue.get("details", {}).get("text", response.text)
                    }
            except:
                pass
            return {"status": "error", "message": f"Failed to search appointments: {response.text}"}

    except Exception as e:
        return {"status": "error", "message": f"An unexpected error occurred: {str(e)}"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000)