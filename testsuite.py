import unittest
import requests

class TestJWKSServer(unittest.TestCase):
    base_url = "http://localhost:8080"

    def test_auth_endpoint(self):
        response = requests.post(f"{self.base_url}/auth")
        self.assertEqual(response.status_code, 405)  # POST not allowed

    def test_well_known_jwks_endpoint(self):
        response = requests.get(f"{self.base_url}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-type"], "application/json")

    def test_register_endpoint(self):
        username = "test_user"
        email = "test@example.com"
        response = requests.post(f"{self.base_url}/register", json={"username": username, "email": email})
        self.assertIn(response.status_code, [200, 201])
        password = response.json().get("password")
        self.assertIsNotNone(password)

        # Test if user registration is successful by trying to authenticate with the generated password
        response = requests.post(f"{self.base_url}/auth", json={"username": username, "password": password})
        self.assertEqual(response.status_code, 200)

    def test_invalid_endpoint(self):
        response = requests.get(f"{self.base_url}/invalid_endpoint")
        self.assertEqual(response.status_code, 405)  # Method not allowed

if __name__ == "__main__":
    unittest.main()
