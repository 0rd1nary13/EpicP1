# src/epic_auth.py

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
    'redirect_uri': 'https://4aaa-67-168-56-39.ngrok-free.app/epic-sandbox/callback',
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
        <h1>Epic Patient Portal Login</h1>
        <p>Current Configuration:</p>
        <pre>
        Client ID: {CONFIG['client_id']}
        Redirect URI: {CONFIG['redirect_uri']}
        Epic Base URL: {CONFIG['epic_base_url']}
        Scope: {CONFIG['scope']}
        </pre>
        <a href="/login">Click here to login</a>
    '''


@app.route('/login')
def login():
    try:
        # Generate PKCE code verifier and challenge
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)
        session['code_verifier'] = code_verifier

        # Prepare authorization parameters for standalone launch
        auth_params = {
            'response_type': 'code',
            'client_id': CONFIG['client_id'],
            'redirect_uri': CONFIG['redirect_uri'],
            'scope': CONFIG['scope'],
            'state': secrets.token_hex(16),
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'aud': 'https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4'  # Only if needed
        }

        session['oauth_state'] = auth_params['state']

        # Build authorization URL
        auth_url = f"{CONFIG['epic_base_url']}/oauth2/authorize?{urlencode(auth_params)}"

        print(f"Auth URL: {auth_url}")  # Debug print
        return redirect(auth_url)
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/epic-sandbox/callback')
def callback():
    try:
        print("Callback args:", request.args)

        error = request.args.get('error')
        if error:
            return f'Error: {error}<br>Description: {request.args.get("error_description")}'

        if request.args.get('state') != session.get('oauth_state'):
            return 'Invalid state parameter', 400

        code = request.args.get('code')
        if not code:
            return 'No authorization code received', 400

        token_params = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': CONFIG['redirect_uri'],
            'client_id': CONFIG['client_id'],
            'code_verifier': session.get('code_verifier')
        }

        token_url = f"{CONFIG['epic_base_url']}/oauth2/token"

        print(f"Token request to: {token_url}")
        print(f"Token params: {token_params}")

        token_response = requests.post(
            token_url,
            data=token_params,
            verify=False
        )

        print(f"Token response: {token_response.status_code} - {token_response.text}")

        if token_response.status_code != 200:
            return f'Token exchange failed: {token_response.text}', 400

        tokens = token_response.json()
        session['access_token'] = tokens['access_token']
        if 'refresh_token' in tokens:
            session['refresh_token'] = tokens['refresh_token']

        return redirect('/patient-info')
    except Exception as e:
        print(f"Callback error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/patient-info')
def patient_info():
    if 'access_token' not in session:
        return redirect('/login')

    try:
        headers = {
            'Authorization': f"Bearer {session['access_token']}",
            'Accept': 'application/json'
        }

        patient_url = f"{CONFIG['fhir_api_base']}/Patient/me"
        response = requests.get(
            patient_url,
            headers=headers,
            verify=False
        )

        if response.status_code == 200:
            patient_data = response.json()
            return f'''
                <h1>Patient Information</h1>
                <pre>{json.dumps(patient_data, indent=2)}</pre>
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
    app.config['PROPAGATE_EXCEPTIONS'] = True
    print("Starting server with configuration:")
    print(json.dumps(CONFIG, indent=2))
    app.run(port=3000, debug=True)
