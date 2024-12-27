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
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CallbackHandler(BaseHTTPRequestHandler):
    code = None
    state = None
    error = None

    def do_GET(self):
        try:
            parsed_url = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed_url.query)

            if '/callback' in self.path:
                CallbackHandler.code = params.get('code', [None])[0]
                CallbackHandler.state = params.get('state', [None])[0]
                CallbackHandler.error = params.get('error', [None])[0]

                response_html = """
                <html>
                <head><title>Authorization Complete</title></head>
                <body style="text-align: center; font-family: Arial, sans-serif; margin-top: 50px;">
                    <h2>Authorization Complete</h2>
                    <p>You can close this window and return to the application.</p>
                    <script>
                        setTimeout(function() { window.close(); }, 3000);
                    </script>
                </body>
                </html>
                """

                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(response_html.encode('utf-8'))

                threading.Thread(target=self.server.shutdown).start()
        except Exception as e:
            logger.error(f"Callback error: {str(e)}")

    def log_message(self, format, *args):
        return


class EpicFHIRClient:
    def __init__(self):
        # Use non-production Epic FHIR sandbox settings
        self.config = {
            'client_id': '4bbe2c64-79c6-47fc-a322-23ee11cc5811',  # Non-production client ID
            'redirect_uri': 'http://localhost:3000/callback',
            'base_fhir_url': 'https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4',
            'auth_base_url': 'https://fhir.epic.com/interconnect-fhir-oauth/oauth2',
            'scope': ' '.join([
                'launch/patient',
                'openid',
                'fhirUser',
                'patient/*.read',
                'offline_access'
            ])
        }
        self.access_token = None
        self.patient_id = None
        self.smart_configuration = None

    def discover_endpoints(self, iss=None):
        """Discover authorization endpoints using SMART configuration"""
        base_url = iss if iss else self.config['base_fhir_url']
        well_known_url = f"{base_url}/.well-known/smart-configuration"

        try:
            response = requests.get(well_known_url)
            if response.status_code == 200:
                self.smart_configuration = response.json()
                return self.smart_configuration
        except Exception as e:
            logger.error(f"Error discovering endpoints: {e}")

        # Fallback to default endpoints
        return {
            'authorization_endpoint': f"{self.config['auth_base_url']}/authorize",
            'token_endpoint': f"{self.config['auth_base_url']}/token"
        }

    def start_auth(self, launch=None, iss=None):
        """Start SMART on FHIR authorization"""
        state = str(uuid.uuid4())
        code_verifier, code_challenge = self._generate_pkce_pair()

        # Get authorization endpoint
        endpoints = self.discover_endpoints(iss)
        auth_endpoint = endpoints.get('authorization_endpoint',
                                      f"{self.config['auth_base_url']}/authorize")

        # Build authorization parameters
        auth_params = {
            'response_type': 'code',
            'client_id': self.config['client_id'],
            'redirect_uri': self.config['redirect_uri'],
            'scope': self.config['scope'],
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'aud': iss if iss else self.config['base_fhir_url']
        }

        if launch:
            auth_params['launch'] = launch

        auth_url = f"{auth_endpoint}?{urllib.parse.urlencode(auth_params)}"

        # Start callback server
        server = HTTPServer(('localhost', 3000), CallbackHandler)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        # Open browser for authorization
        webbrowser.open(auth_url)
        server.serve_forever()

        # Verify state parameter
        if CallbackHandler.state != state:
            raise ValueError("State parameter mismatch")

        if CallbackHandler.error:
            raise Exception(f"Authorization failed: {CallbackHandler.error}")

        return CallbackHandler.code, code_verifier

    def complete_auth(self, auth_code, code_verifier):
        """Complete SMART on FHIR authorization"""
        token_endpoint = (self.smart_configuration or {}).get('token_endpoint',
                                                              f"{self.config['auth_base_url']}/token")

        token_params = {
            'grant_type': 'authorization_code',
            'code': auth_code,
            'redirect_uri': self.config['redirect_uri'],
            'client_id': self.config['client_id'],
            'code_verifier': code_verifier
        }

        response = requests.post(
            token_endpoint,
            data=token_params,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

        token_data = response.json()

        if 'access_token' not in token_data:
            raise Exception(f"Token error: {token_data.get('error_description', 'Unknown error')}")

        self.access_token = token_data['access_token']
        self.patient_id = token_data.get('patient')

        return token_data

    def _generate_pkce_pair(self):
        """Generate PKCE code verifier and challenge"""
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        return code_verifier, code_challenge

    def get_patient_demographics(self):
        """Get patient demographics"""
        if not self.patient_id:
            raise ValueError("No patient context available")

        response = requests.get(
            f"{self.config['base_fhir_url']}/Patient/{self.patient_id}",
            headers=self._get_headers()
        )
        return response.json()

    def get_patient_observations(self, code=None):
        """Get patient observations"""
        url = f"{self.config['base_fhir_url']}/Observation?patient={self.patient_id}"
        if code:
            url += f"&code={code}"

        response = requests.get(url, headers=self._get_headers())
        return response.json()

    def _get_headers(self):
        """Get request headers with access token"""
        if not self.access_token:
            raise ValueError("No access token available")

        return {
            'Authorization': f'Bearer {self.access_token}',
            'Accept': 'application/json'
        }


def save_response(data, filename):
    """Save API response to file"""
    os.makedirs('epic_responses', exist_ok=True)
    filepath = os.path.join('epic_responses', filename)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    logger.info(f"Saved response to {filepath}")


def main():
    client = EpicFHIRClient()

    try:
        print("\n=== Epic SMART on FHIR Patient App ===")
        print("\nInitiating patient context launch...")

        # Start authorization
        print("\nStarting authorization...")
        auth_code, code_verifier = client.start_auth()

        if not auth_code:
            print("Failed to get authorization code")
            return

        print("Completing authorization...")
        token_data = client.complete_auth(auth_code, code_verifier)
        save_response(token_data, 'token.json')

        print("\n✓ Authorization successful")
        print(f"✓ Patient context established: {client.patient_id}")

        # Get patient data
        print("\nFetching patient data...")

        demographics = client.get_patient_demographics()
        save_response(demographics, 'patient_demographics.json')

        name = demographics.get('name', [{}])[0].get('text', 'Unknown')
        print(f"\nPatient: {name}")
        print(f"ID: {client.patient_id}")

        # Get observations
        print("\nFetching observations...")
        observations = client.get_patient_observations()
        save_response(observations, 'patient_observations.json')

        # Display summary
        entries = observations.get('entry', [])
        print(f"\nFound {len(entries)} observations")

        print("\nData saved to 'epic_responses' directory:")
        print("- token.json")
        print("- patient_demographics.json")
        print("- patient_observations.json")

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        print("\nError occurred. Please check:")
        print("1. Valid launch context (if launching from EHR)")
        print("2. Correct credentials (if using sandbox)")
        print("3. Internet connection")
        raise


if __name__ == "__main__":
    main()
