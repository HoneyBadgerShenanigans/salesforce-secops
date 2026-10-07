"""Salesforce Authentication Module.

Supports:
1. OAuth 2.0 JWT Bearer Token Flow (RFC 7523) using RSA private key
2. OAuth 2.0 Client Credentials Grant
3. OAuth 2.0 Username-Password Grant
"""

import base64
import json
import logging
import time
import urllib.parse
import uuid
from typing import Any, Dict, Optional
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

logger = logging.getLogger(__name__)


def _base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


class SalesforceAuth:
    """Base Salesforce authentication class."""

    def __init__(self, login_url: str = "https://login.salesforce.com"):
        parsed = urllib.parse.urlparse(login_url)
        if parsed.scheme.lower() != "https":
            raise ValueError(f"Security Error: Insecure scheme in login_url '{login_url}'. HTTPS is required.")
        self.login_url = login_url.rstrip("/")
        self._access_token: Optional[str] = None
        self._instance_url: Optional[str] = None
        self._token_expiry: float = 0.0

    @property
    def access_token(self) -> str:
        """Get a valid access token, refreshing if necessary."""
        if not self._access_token or time.time() >= self._token_expiry - 60:
            self.authenticate()
        return self._access_token or ""

    @property
    def instance_url(self) -> str:
        """Get the base instance URL for API requests."""
        if not self._instance_url:
            self.authenticate()
        return self._instance_url or ""

    def authenticate(self) -> Dict[str, Any]:
        """Authenticate with Salesforce and return token response."""
        raise NotImplementedError("Subclasses must implement authenticate()")


class SalesforceJWTAuth(SalesforceAuth):
    """OAuth 2.0 JWT Bearer Token authentication (RFC 7523).

    Uses an RSA private key to generate a signed JWT assertion for the Connected
    App or External Client App configured in Salesforce.
    """

    def __init__(
        self,
        client_id: str,
        username: str,
        private_key: str,
        login_url: str = "https://login.salesforce.com",
        token_lifetime_seconds: int = 180,
    ):
        super().__init__(login_url=login_url)
        self.client_id = client_id
        self.username = username
        self.private_key_pem = private_key
        self.token_lifetime_seconds = token_lifetime_seconds

    def _create_signed_jwt(self) -> str:
        """Create and sign an RS256 JWT assertion."""
        header = {"alg": "RS256", "typ": "JWT"}
        now = int(time.time())
        claims = {
            "iss": self.client_id,
            "sub": self.username,
            "aud": self.login_url,
            "exp": now + self.token_lifetime_seconds,
            "nbf": now - 30,
            "jti": str(uuid.uuid4()),
        }

        header_b64 = _base64url_encode(
            json.dumps(header, separators=(",", ":")).encode("utf-8")
        )
        claims_b64 = _base64url_encode(
            json.dumps(claims, separators=(",", ":")).encode("utf-8")
        )
        signing_input = f"{header_b64}.{claims_b64}".encode("utf-8")

        # Load private key (supports PKCS#8 or PKCS#1)
        key_bytes = self.private_key_pem.encode("utf-8")
        private_key = load_pem_private_key(key_bytes, password=None)

        signature = private_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        sig_b64 = _base64url_encode(signature)

        return f"{header_b64}.{claims_b64}.{sig_b64}"

    def authenticate(self) -> Dict[str, Any]:
        """Request OAuth token using JWT assertion."""
        assertion = self._create_signed_jwt()
        token_endpoint = f"{self.login_url}/services/oauth2/token"

        payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        }

        logger.info("Authenticating to Salesforce via OAuth 2.0 JWT Bearer flow (%s)...", self.login_url)
        response = requests.post(
            token_endpoint,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )

        if not response.ok:
            error_msg = f"HTTP {response.status_code}"
            try:
                err_json = response.json()
                err_code = err_json.get("error", "")
                err_desc = err_json.get("error_description", "")
                if err_code or err_desc:
                    error_msg = f"{err_code}: {err_desc}".strip(": ")
            except Exception:
                pass
            raise RuntimeError(f"Salesforce JWT authentication failed ({error_msg})")

        data = response.json()
        self._access_token = data["access_token"]
        raw_instance_url = data.get("instance_url", self.login_url)
        parsed_inst = urllib.parse.urlparse(raw_instance_url)
        if parsed_inst.scheme.lower() != "https":
            raise ValueError(f"Security Error: Insecure scheme in returned instance URL '{raw_instance_url}'.")
        self._instance_url = raw_instance_url
        # Salesforce JWT tokens typically expire in 2 hours or per session policy
        self._token_expiry = time.time() + 3600
        logger.info("Successfully authenticated to Salesforce instance: %s", self._instance_url)
        return data


class SalesforcePasswordAuth(SalesforceAuth):
    """OAuth 2.0 Username-Password authentication flow (Deprecated by Salesforce)."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        username: str,
        password: str,
        security_token: str = "",
        login_url: str = "https://login.salesforce.com",
    ):
        super().__init__(login_url=login_url)
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.security_token = security_token

        logger.warning(
            "SECURITY DEPRECATION WARNING: Salesforce OAuth Username-Password flow is deprecated and incompatible with MFA. "
            "Please migrate to OAuth 2.0 JWT Bearer flow (auth_type: jwt)."
        )

    def authenticate(self) -> Dict[str, Any]:
        """Request OAuth token using username, password and security token."""
        token_endpoint = f"{self.login_url}/services/oauth2/token"
        payload = {
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": self.username,
            "password": f"{self.password}{self.security_token}",
        }

        logger.info("Authenticating to Salesforce via Password flow (%s)...", self.login_url)
        response = requests.post(token_endpoint, data=payload, timeout=30)
        if not response.ok:
            error_msg = f"HTTP {response.status_code}"
            try:
                err_json = response.json()
                err_code = err_json.get("error", "")
                err_desc = err_json.get("error_description", "")
                if err_code or err_desc:
                    error_msg = f"{err_code}: {err_desc}".strip(": ")
            except Exception:
                pass
            raise RuntimeError(f"Salesforce Password authentication failed ({error_msg})")

        data = response.json()
        self._access_token = data["access_token"]
        raw_instance_url = data.get("instance_url", self.login_url)
        parsed_inst = urllib.parse.urlparse(raw_instance_url)
        if parsed_inst.scheme.lower() != "https":
            raise ValueError(f"Security Error: Insecure scheme in returned instance URL '{raw_instance_url}'.")
        self._instance_url = raw_instance_url
        self._token_expiry = time.time() + 3600
        return data
