from config import vuln_app
import os

'''
 Decide if you want to serve a vulnerable version or not!
 DO NOTE: some functionalities will still be vulnerable even if the value is set to 0
          as it is a matter of bad practice. Such an example is the debug endpoint.
'''
vuln = int(os.getenv('vulnerable', 1))
# vuln=1
# token alive for how many seconds?
alive = int(os.getenv('tokentimetolive', 60))

def test_root_path():
    with vuln_app.app.test_client() as client:
        response = client.get("/")
        assert response.status_code == 200
        assert b"Welcome" in response.data  # Check for specific content in the response

def test_debug_endpoint():
    with vuln_app.app.test_client() as client:
        response = client.get("/debug")
        if vuln:
            assert response.status_code == 200
            assert b"Debug Info" in response.data  # Check for debug information
        else:
            assert response.status_code == 404  # Debug endpoint should not exist in non-vulnerable mode

def test_token_generation():
    with vuln_app.app.test_client() as client:
        response = client.post("/generate-token", json={"username": "testuser"})
        assert response.status_code == 200
        assert "token" in response.json  # Ensure the response contains a token

def test_protected_endpoint_with_valid_token():
    with vuln_app.app.test_client() as client:
        # Generate a token first
        token_response = client.post("/generate-token", json={"username": "testuser"})
        token = token_response.json.get("token")
        
        # Access a protected endpoint with the token
        response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        assert b"Access Granted" in response.data

def test_protected_endpoint_with_invalid_token():
    with vuln_app.app.test_client() as client:
        # Access a protected endpoint with an invalid token
        response = client.get("/protected", headers={"Authorization": "Bearer invalidtoken"})
        assert response.status_code == 401
        assert b"Invalid Token" in response.data

def test_404_not_found():
    with vuln_app.app.test_client() as client:
        response = client.get("/nonexistent-endpoint")
        assert response.status_code == 404