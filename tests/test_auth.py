"""Unit tests for Salesforce Authentication."""

import json
import unittest
from unittest.mock import MagicMock, patch
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from salesforce_secops.auth import SalesforceJWTAuth, SalesforcePasswordAuth


class TestSalesforceAuth(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Generate an RSA private key for testing
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.private_key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

    def test_jwt_assertion_format(self):
        auth = SalesforceJWTAuth(
            client_id="TEST_CLIENT_ID_12345",
            username="secops@example.com",
            private_key=self.private_key_pem,
            login_url="https://login.salesforce.com",
        )

        jwt_assertion = auth._create_signed_jwt()
        parts = jwt_assertion.split(".")
        self.assertEqual(len(parts), 3, "JWT must consist of 3 base64url segments")

    @patch("salesforce_secops.auth.requests.post")
    def test_jwt_authenticate_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "access_token": "mock_access_token_xyz",
            "instance_url": "https://company.my.salesforce.com",
        }
        mock_post.return_value = mock_response

        auth = SalesforceJWTAuth(
            client_id="CLIENT_ID",
            username="secops@example.com",
            private_key=self.private_key_pem,
        )

        token_data = auth.authenticate()
        self.assertEqual(token_data["access_token"], "mock_access_token_xyz")
        self.assertEqual(auth.access_token, "mock_access_token_xyz")
        self.assertEqual(auth.instance_url, "https://company.my.salesforce.com")

    @patch("salesforce_secops.auth.requests.post")
    def test_jwt_authenticate_failure(self, mock_post):
        mock_response = MagicMock()
        mock_response.ok = False
        mock_response.status_code = 400
        mock_response.text = '{"error": "invalid_grant"}'
        mock_post.return_value = mock_response

        auth = SalesforceJWTAuth(
            client_id="CLIENT_ID",
            username="secops@example.com",
            private_key=self.private_key_pem,
        )

        with self.assertRaises(RuntimeError):
            auth.authenticate()


if __name__ == "__main__":
    unittest.main()
