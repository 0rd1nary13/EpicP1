import requests
import json
import uuid
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import base64
import hashlib
import os
import urllib.parse
from datetime import datetime


class CallbackHandler(BaseHTTPRequestHandler):
    code = None

    def do_GET(self):
        if '/callback' in self.path:
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            CallbackHandler.code = params.get('code', [None])[0]

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"Authorization code received. You can close this window.")

            # Stop the server after receiving the code
            threading.Thread(target=self.server.shutdown).start()


class EpicSandboxClient:
    def __init__(self):
        self.base_url = "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4"
        self.auth_base_url = "https://fhir.epic.com/interconnect-fhir-oauth/oauth2"
        self.client_id = "4bbe2c64-79c6-47fc-a322-23ee11cc5811"  # Replace with your client ID
        self.redirect_uri = "http://localhost:3000/callback"
        self.scope = "launch/patient Patient.read"

    def generate_pkce_pair(self):
        """Generate PKCE code verifier and challenge"""
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
        code_verifier = code_verifier.replace('=', '')

        code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
        code_challenge = code_challenge.replace('=', '')

        return code_verifier, code_challenge

    def get_auth_code(self):
        """Start authorization flow and get auth code"""
        state = str(uuid.uuid4())
        code_verifier, code_challenge = self.generate_pkce_pair()

        # Create authorization URL
        auth_params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': self.scope,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }

        auth_url = f"{self.auth_base_url}/authorize?{urllib.parse.urlencode(auth_params)}"

        # Start local server to receive callback
        server = HTTPServer(('localhost', 3000), CallbackHandler)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        # Open browser for authorization
        webbrowser.open(auth_url)

        # Wait for the callback
        server.serve_forever()

        return CallbackHandler.code, code_verifier

    def get_token(self, auth_code, code_verifier):
        """Exchange authorization code for access token"""
        token_params = {
            'grant_type': 'authorization_code',
            'code': auth_code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id,
            'code_verifier': code_verifier
        }

        response = requests.post(
            f"{self.auth_base_url}/token",
            data=token_params,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

        return response.json()

    def refresh_token(self, refresh_token):
        """Get new access token using refresh token"""
        token_params = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': self.client_id
        }

        response = requests.post(
            f"{self.auth_base_url}/token",
            data=token_params,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

        return response.json()

    def get_patient(self, access_token, patient_id=None):
        """Get patient information"""
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }

        url = f"{self.base_url}/Patient/{patient_id}" if patient_id else f"{self.base_url}/Patient"
        response = requests.get(url, headers=headers)

        return response.json()

    def get_conditions(self, access_token, patient_id):
        """Get patient conditions"""
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }

        response = requests.get(
            f"{self.base_url}/Condition?patient={patient_id}",
            headers=headers
        )

        return response.json()

    def get_medications(self, access_token, patient_id):
        """Get patient medications"""
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }

        response = requests.get(
            f"{self.base_url}/MedicationRequest?patient={patient_id}",
            headers=headers
        )

        return response.json()

    def get_observations(self, access_token, patient_id):
        """Get patient observations"""
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }

        response = requests.get(
            f"{self.base_url}/Observation?patient={patient_id}",
            headers=headers
        )

        return response.json()


def main():
    client = EpicSandboxClient()

    print("Starting Epic FHIR Authorization Flow...")
    auth_code, code_verifier = client.get_auth_code()

    if auth_code:
        print("\nGot authorization code. Getting access token...")
        token_response = client.get_token(auth_code, code_verifier)

        if 'access_token' in token_response:
            access_token = token_response['access_token']
            print("\nSuccessfully got access token!")

            # Get patient ID if needed
            patient_id = input("\nEnter patient ID (or press Enter to list all patients): ").strip()

            try:
                # Get patient information
                print("\nFetching patient information...")
                patient_data = client.get_patient(access_token, patient_id if patient_id else None)
                print(f"Patient Data: {json.dumps(patient_data, indent=2)}")

                if patient_id:
                    # Get conditions
                    print("\nFetching conditions...")
                    conditions = client.get_conditions(access_token, patient_id)
                    print(f"Conditions: {json.dumps(conditions, indent=2)}")

                    # Get medications
                    print("\nFetching medications...")
                    medications = client.get_medications(access_token, patient_id)
                    print(f"Medications: {json.dumps(medications, indent=2)}")

                    # Get observations
                    print("\nFetching observations...")
                    observations = client.get_observations(access_token, patient_id)
                    print(f"Observations: {json.dumps(observations, indent=2)}")

            except Exception as e:
                print(f"Error accessing FHIR resources: {e}")
        else:
            print("Error getting access token:", token_response)
    else:
        print("Failed to get authorization code")


if __name__ == "__main__":
    main()
