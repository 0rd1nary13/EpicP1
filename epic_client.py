import requests
import urllib.parse
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import uuid
import json
import hashlib
import base64
import os


class EpicClient:
    def __init__(self):
        self.client_id = "8d752ddc-7100-4d9d-9bf9-f1e2846afe5e"
        self.redirect_uri = "http://localhost:8000"
        self.base_url = "https://fhir.epic.com/interconnect-fhir-oauth"
        self.fhir_base = f"{self.base_url}/api/FHIR/R4"

    def generate_pkce_pair(self):
        """Generate PKCE code verifier and challenge"""
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
        code_verifier = code_verifier.replace('=', '')  # Remove padding
        
        # Generate S256 challenge
        code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
        code_challenge = code_challenge.replace('=', '')  # Remove padding
        
        return code_verifier, code_challenge

    def get_metadata(self, iss=None):
        """Step 2: Get authorization endpoints from metadata or SMART configuration"""
        # Use provided ISS or default base URL
        base_endpoint = iss if iss else self.base_url
        
        # Try SMART configuration first (newer versions)
        smart_config_url = f"{base_endpoint}/api/FHIR/R4/.well-known/smart-configuration"
        headers = {
            'Accept': 'application/json',
            'Epic-Client-ID': self.client_id
        }
        
        print(f"\nTrying SMART configuration endpoint: {smart_config_url}")
        try:
            response = requests.get(smart_config_url, headers=headers)
            if response.status_code == 200:
                config = response.json()
                return {
                    'authorize_endpoint': config.get('authorization_endpoint'),
                    'token_endpoint': config.get('token_endpoint')
                }
        except Exception as e:
            print(f"SMART configuration request failed: {e}")
        
        # Fallback to metadata endpoint
        metadata_url = f"{base_endpoint}/api/FHIR/R4/metadata"
        headers = {
            'Accept': 'application/fhir+json',
            'Epic-Client-ID': self.client_id
        }
        
        print(f"\nTrying metadata endpoint: {metadata_url}")
        try:
            response = requests.get(metadata_url, headers=headers)
            if response.status_code == 200:
                metadata = response.json()
                endpoints = {}
                
                # Extract OAuth URLs from metadata
                for ext in metadata.get('extension', []):
                    if ext.get('url') == 'http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris':
                        for uri in ext.get('extension', []):
                            if uri.get('url') == 'authorize':
                                endpoints['authorize_endpoint'] = uri.get('valueUri')
                            elif uri.get('url') == 'token':
                                endpoints['token_endpoint'] = uri.get('valueUri')
                
                if endpoints:
                    return endpoints
        except Exception as e:
            print(f"Metadata request failed: {e}")
        
        # Fallback to default endpoints
        return {
            'authorize_endpoint': f"{self.base_url}/oauth2/authorize",
            'token_endpoint': f"{self.base_url}/oauth2/token"
        }

    def authorize(self, launch=None, iss=None, use_post=True):
        """Step 3: Request authorization code using POST or GET"""
        # Get endpoints from metadata
        endpoints = self.get_metadata(iss)
        authorize_endpoint = endpoints.get('authorize_endpoint')
        
        # Generate state and PKCE values
        state = str(uuid.uuid4())  # Random state with sufficient entropy
        code_verifier, code_challenge = self.generate_pkce_pair()
        
        # Store code_verifier for token exchange
        self.code_verifier = code_verifier
        
        # Construct authorization parameters
        auth_params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'state': state,
            'scope': 'launch openid fhirUser patient/*.read',  # Added OpenID scopes
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        
        # Add launch parameter if provided (EHR launch flow)
        if launch:
            auth_params['launch'] = launch
            
        # Add aud parameter if iss provided (required from May 2023)
        if iss:
            auth_params['aud'] = iss
        
        if use_post:
            # Create an HTML form for POST submission
            html_form = f"""
            <html>
            <body onload="document.forms[0].submit()">
                <form method="post" action="{authorize_endpoint}">
                    {''.join(f'<input type="hidden" name="{k}" value="{v}">' for k, v in auth_params.items())}
                </form>
            </body>
            </html>
            """
            
            # Save the form to a temporary file and open it
            with open('auth_form.html', 'w') as f:
                f.write(html_form)
            webbrowser.open('file://' + os.path.abspath('auth_form.html'))
        else:
            # Use GET request
            auth_url = f"{authorize_endpoint}?{urllib.parse.urlencode(auth_params)}"
            webbrowser.open(auth_url)
        
        print("\nAuthorization Request Details:")
        print(f"Endpoint: {authorize_endpoint}")
        print("Parameters:")
        for k, v in auth_params.items():
            print(f"  {k}: {v}")
        
        print("\nWaiting for authorization code from redirect...")
        code = input("Enter the authorization code: ")
        
        # Clean up temporary file if it exists
        if use_post and os.path.exists('auth_form.html'):
            os.remove('auth_form.html')
        
        return code, state

    def get_patient_data(self, access_token, patient_id):
        """Step 6: Use FHIR APIs to access patient data"""
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        
        response = requests.get(
            f"{self.fhir_base}/Patient/{patient_id}",
            headers=headers
        )
        
        return response.json()


def main():
    client = EpicClient()

    print("Starting authorization flow...")
    client.authorize()

    # After authorization, fetch patient data
    # Replace 'example_patient_id' with an actual patient ID from your sandbox
    patient_id = "example_patient_id"
    client.fetch_patient_data(patient_id)


if __name__ == "__main__":
    main()
