import traceback

import requests
import base64
import hashlib
import os
import secrets
import json
import urllib3
from urllib.parse import urlencode
from flask import Flask, request, redirect, session, jsonify

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# OAuth 2.0 Configuration for Epic's sandbox
CONFIG = {
    'client_id': '4bbe2c64-79c6-47fc-a322-23ee11cc5811',
    'redirect_uri': 'https://7b26-137-110-45-62.ngrok-free.app/epic-sandbox/callback',
    'epic_base_url': 'https://fhir.epic.com/interconnect-fhir-oauth',
    # Only requesting basic scopes for standalone launch
    'scope': 'openid fhirUser',
    'fhir_api_base': 'https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4'
}


def generate_code_verifier():
    token = secrets.token_urlsafe(64)
    return token[:128]


def generate_code_challenge(verifier):
    sha256 = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(sha256).decode('utf-8').rstrip('=')


@app.route('/')
def index():
    return f'''
        <h1>Epic OAuth Test App</h1>
        <p>Current Configuration:</p>
        <pre>{json.dumps(CONFIG, indent=2)}</pre>
        <p>Current Session:</p>
        <pre>{json.dumps({k: v for k, v in session.items()}, indent=2)}</pre>
        <a href="/login">Start Login Process</a>
    '''


@app.route('/login')
def login():
    try:
        print("\n========== LOGIN ATTEMPT ==========")
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)
        session['code_verifier'] = code_verifier

        # Fix the redirect_uri - remove any spaces
        redirect_uri = CONFIG['redirect_uri'].strip()

        auth_params = {
            'response_type': 'code',
            'client_id': CONFIG['client_id'],
            'redirect_uri': redirect_uri,  # Use the cleaned redirect_uri
            'scope': CONFIG['scope'],
            'state': secrets.token_hex(16),
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'aud': CONFIG['fhir_api_base']
        }

        session['oauth_state'] = auth_params['state']
        auth_url = f"{CONFIG['epic_base_url']}/oauth2/authorize?{urlencode(auth_params)}"

        print("Authorization URL:", auth_url)
        return redirect(auth_url)
    except Exception as e:
        print(f"Login error: {str(e)}")
        return f"Error during login: {str(e)}", 500

@app.before_request
def log_request():
    print("\n========== REQUEST RECEIVED ==========")
    print(f"Path: {request.path}")
    print(f"Method: {request.method}")
    print(f"URL: {request.url}")
    print(f"Headers: {dict(request.headers)}")
    if request.args:
        print(f"Query Parameters: {dict(request.args)}")

@app.route('/epic-sandbox/callback')
def callback():
    print("\n========== CALLBACK RECEIVED ==========")
    print(f"Full Callback URL: {request.url}")
    print("\nQuery Parameters:")
    for key, value in request.args.items():
        print(f"{key}: {value}")

    try:
        code = request.args.get('code')
        if code:
            print("\nAuthorization Code Received:")
            print("=" * 50)
            print(code)
            print("=" * 50)

        # Continue with your existing code...

    except Exception as e:
        print(f"Callback error: {str(e)}")
        return f"Error in callback: {str(e)}", 500

@app.route('/patient-info')
def patient_info():
    if 'access_token' not in session:
        return redirect('/login')

    try:
        headers = {
            'Authorization': f"Bearer {session['access_token']}",
            'Accept': 'application/json'
        }

        # If we have a specific patient ID, use it
        patient_id = session.get('patient', 'me')
        patient_url = f"{CONFIG['fhir_api_base']}/Patient/{patient_id}"

        print("\n========== PATIENT INFO REQUEST ==========")
        print(f"URL: {patient_url}")
        print(f"Headers: {headers}")

        response = requests.get(
            patient_url,
            headers=headers,
            verify=False  # Only for development
        )

        print("\n========== PATIENT INFO RESPONSE ==========")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")

        if response.status_code == 200:
            patient_data = response.json()
            return f'''
                <h1>Patient Information</h1>
                <pre>{json.dumps(patient_data, indent=2)}</pre>
                <hr>
                <h2>Access Token Information</h2>
                <p>Token Type: {session.get('token_type')}</p>
                <p>Expires In: {session.get('expires_in')} seconds</p>
                <p>Scope: {session.get('scope')}</p>
                <a href="/logout">Logout</a>
            '''
        else:
            return f'Failed to retrieve patient info: {response.text}'
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


if __name__ == '__main__':
    import logging

    logging.basicConfig(level=logging.DEBUG)

    app.config['PROPAGATE_EXCEPTIONS'] = True
    app.config['SERVER_NAME'] = None

    print("\n========== SERVER STARTING ==========")
    print("CONFIG:", json.dumps(CONFIG, indent=2))
    print("\nRoutes registered:")
    for rule in app.url_map.iter_rules():
        print(f"- {rule}")

    app.run(host='0.0.0.0', port=5000, debug=True)