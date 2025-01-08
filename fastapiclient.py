import base64
import hashlib
import json
import secrets
from urllib.parse import urlencode
import requests
import urllib3
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI()

# Add session middleware
app.add_middleware(
    SessionMiddleware,
    secret_key=secrets.token_hex(32),
    session_cookie="epic_session"
)

# OAuth 2.0 Configuration for Epic's sandbox
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
                input {{ padding: 5px; margin: 5px; width: 300px; }}
                pre {{ margin-top: 20px; white-space: pre-wrap; background: #f5f5f5; padding: 10px; }}
                .error {{ color: #721c24; background: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; margin: 10px 0; }}
                .debug-info {{ background: #eee; padding: 10px; margin: 10px 0; }}
                .section {{ 
                    margin-top: 30px; 
                    border-top: 1px solid #ccc; 
                    padding-top: 20px; 
                }}
            </style>
            <script>
                const CODE_VERIFIER = '{code_verifier}';
                const AUTH_URL = '{auth_url}';
                const EXAMPLE_APPOINTMENT_ID = 'elmPBHPxEEEvVLKSSR6xGfQaaeOxoGVxtCt9FlmcwgQ03';

                async function startAuth() {{
                    window.open(AUTH_URL, '_blank');
                }}

                async function submitURL() {{
                    const url = document.getElementById('urlInput').value;
                    try {{
                        const response = await fetch('/process-callback-url', {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ 
                                url: url,
                                code_verifier: CODE_VERIFIER
                            }})
                        }});
                        const data = await response.json();
                        document.getElementById('result').textContent = JSON.stringify(data, null, 2);
                    }} catch (error) {{
                        document.getElementById('result').textContent = 'Error: ' + error.message;
                    }}
                }}

                async function fetchAppointment() {{
                    const appointmentId = document.getElementById('appointmentId').value || EXAMPLE_APPOINTMENT_ID;
                    try {{
                        const response = await fetch(`/api/fhir/Appointment/${{appointmentId}}`);
                        const data = await response.json();

                        let formattedResult = '';
                        if (data.status === 'error') {{
                            formattedResult = `ERROR DETAILS:
-------------
Code: ${{data.error_code}}
Severity: ${{data.severity}}
Message: ${{data.message}}

Full Response:
${{JSON.stringify(data, null, 2)}}`;
                        }} else {{
                            formattedResult = JSON.stringify(data, null, 2);
                        }}

                        document.getElementById('appointmentResult').textContent = formattedResult;
                    }} catch (error) {{
                        document.getElementById('appointmentResult').textContent = 'Error: ' + error.message;
                    }}
                }}

                function useExampleId() {{
                    document.getElementById('appointmentId').value = EXAMPLE_APPOINTMENT_ID;
                }}
            </script>
        </head>
        <body>
            <h1>Epic Appointment API Test</h1>

            <div class="section">
                <h3>Step 1: Start Authorization</h3>
                <button onclick="startAuth()">Start Authorization</button>
                <div class="debug-info">
                    <p>Debug Information:</p>
                    <pre>Code Verifier: {code_verifier}</pre>
                    <pre>Code Challenge: {code_challenge}</pre>
                    <pre>State: {state}</pre>
                </div>
            </div>

            <div class="section">
                <h3>Step 2: Enter Callback URL</h3>
                <p>After authorizing, paste the callback URL here:</p>
                <textarea id="urlInput" placeholder="Paste the callback URL here"></textarea>
                <button onclick="submitURL()">Process URL</button>
                <h4>Token Exchange Results:</h4>
                <pre id="result"></pre>
            </div>

            <div class="section">
                <h3>Step 3: Test Appointment API</h3>
                <p>After getting the token, test the Appointment API:</p>
                <div class="input-group">
                    <input type="text" id="appointmentId" 
                           placeholder="Enter Appointment ID">
                    <button onclick="useExampleId()">Use Example ID</button>
                    <button onclick="fetchAppointment()">Fetch Appointment</button>
                </div>
                <p style="color: #666; font-size: 0.9em;">
                    Example ID: elmPBHPxEEEvVLKSSR6xGfQaaeOxoGVxtCt9FlmcwgQ03
                </p>
                <h4>Appointment API Response:</h4>
                <pre id="appointmentResult"></pre>
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

        if not url or not code_verifier:
            raise HTTPException(status_code=400, detail="Missing URL or code_verifier")

        from urllib.parse import urlparse, parse_qs
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        code = params.get('code', [None])[0]
        if not code:
            raise HTTPException(status_code=400, detail="No authorization code found in URL")

        token_params = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': CONFIG['redirect_uri'].strip(),
            'client_id': CONFIG['client_id'],
            'code_verifier': code_verifier
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        token_response = requests.post(
            f"{CONFIG['epic_base_url']}/oauth2/token",
            data=token_params,
            headers=headers,
            verify=False
        )

        if token_response.status_code == 200:
            token_data = token_response.json()
            request.session['access_token'] = token_data.get('access_token')
            return {
                "status": "success",
                "token_data": token_data
            }
        else:
            return {
                "status": "error",
                "message": f"Failed to get access token: {token_response.text}",
                "request_details": {
                    "params": token_params,
                    "headers": headers
                }
            }

    except Exception as e:
        print(f"Error processing URL: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }


@app.get("/api/fhir/{resource_type}/{resource_id}")
async def get_fhir_resource(request: Request, resource_type: str, resource_id: str):
    try:
        access_token = request.session.get('access_token')
        if not access_token:
            return {
                "status": "error",
                "error_code": "4118",
                "severity": "Fatal",
                "message": "User not authorized for request: No access token found"
            }

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }

        fhir_url = f"{CONFIG['fhir_api_base']}/{resource_type}/{resource_id}"

        print("\n========== FHIR API REQUEST ==========")
        print(f"URL: {fhir_url}")
        print(f"Headers: {headers}")

        response = requests.get(
            fhir_url,
            headers=headers,
            verify=False
        )

        print("\n========== FHIR API RESPONSE ==========")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")

        if response.status_code == 200:
            return {
                "status": "success",
                "data": response.json()
            }
        elif response.status_code == 404:
            return {
                "status": "error",
                "error_code": "4102",
                "severity": "Fatal",
                "message": f"The read resource request contained an invalid ID: {resource_type}/{resource_id}"
            }
        elif response.status_code == 401:
            return {
                "status": "error",
                "error_code": "4118",
                "severity": "Fatal",
                "message": "User not authorized for request"
            }
        elif response.status_code == 403:
            return {
                "status": "error",
                "error_code": "4130",
                "severity": "Fatal",
                "message": "Break-the-Glass security does not authorize you to access the selected resource"
            }
        else:
            try:
                error_response = response.json()
                return {
                    "status": "error",
                    "error_code": error_response.get('resourceType', 'Unknown'),
                    "severity": "Fatal",
                    "message": f"Failed to fetch {resource_type} data: {error_response}",
                    "raw_response": error_response
                }
            except:
                return {
                    "status": "error",
                    "error_code": "59177",
                    "severity": "Fatal",
                    "message": f"An unexpected error occurred: Status {response.status_code}",
                    "raw_response": response.text
                }

    except Exception as e:
        print(f"Error fetching {resource_type} data: {str(e)}")
        return {
            "status": "error",
            "error_code": "59177",
            "severity": "Fatal",
            "message": f"An unexpected internal error has occurred: {str(e)}"
        }


if __name__ == "__main__":
    import uvicorn

    print("\n========== SERVER STARTING ==========")
    print("CONFIG:", json.dumps(CONFIG, indent=2))
    uvicorn.run(app, host="0.0.0.0", port=3000)