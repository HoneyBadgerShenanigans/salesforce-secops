import base64
import os
import stat
import tempfile
import unittest

from salesforce_secops.auth import SalesforceJWTAuth, SalesforcePasswordAuth
from salesforce_secops.checkpoint import FileCheckpointManager
from salesforce_secops.normalizer import SalesforceRecordNormalizer
from salesforce_secops.sf_client import SalesforceClient, validate_timestamp_param


class TestSecurityDefenses(unittest.TestCase):

    def test_soql_injection_rejection_in_timestamps(self):
        """Verify that malformed or malicious timestamp parameters are rejected."""
        malicious_inputs = [
            "2026-01-01' OR 1=1 --",
            "2026-01-01T00:00:00Z; DELETE FROM User",
            "2026-01-01' UNION SELECT Id, Password FROM User --",
            "SELECT * FROM Account",
            "<script>alert(1)</script>",
            "2026-01-01T00:00:00Z' OR Id != null",
        ]

        template = "SELECT Id FROM LoginHistory WHERE LoginTime > :checkpoint"

        for mal_input in malicious_inputs:
            with self.subTest(mal_input=mal_input):
                with self.assertRaises(ValueError) as ctx:
                    SalesforceClient.prepare_query(template, checkpoint=mal_input)
                self.assertIn("Security Validation Error", str(ctx.exception))

    def test_valid_timestamps_accepted(self):
        """Verify valid ISO 8601 timestamps are accepted."""
        valid_inputs = [
            "2026-01-01",
            "2026-01-01T12:00:00Z",
            "2026-01-01T12:00:00.000Z",
            "2026-01-01T12:00:00+00:00",
            "2026-01-01T12:00:00-05:00",
        ]
        template = "SELECT Id FROM LoginHistory WHERE LoginTime > :checkpoint"
        for val in valid_inputs:
            with self.subTest(val=val):
                res = SalesforceClient.prepare_query(template, checkpoint=val)
                self.assertIn(val, res)

    def test_sensitive_credential_redaction(self):
        """Ensure sensitive credentials and auth secrets are automatically masked across all field patterns."""
        normalizer = SalesforceRecordNormalizer(default_object="CustomUserAudit")
        raw_record = {
            "Id": "005123456789012",
            "Username": "admin@example.com",
            "Password": "SuperSecretPassword123!",
            "User_ClientSecret": "cs_live_998877665544",
            "Security_Token": "tok_xyz_secret",
            "Api_Key": "key_abcdef123456",
            "AccessToken": "00D50000000IzUN!AQcAQ...",
            "RefreshToken__c": "1//04testrefreshtoken...",
            "BearerToken": "bearer_abc123",
            "AppSecret__c": "app_secret_value",
            "Secret__c": "raw_secret",
            "EncryptionKey__c": "enc_key_999",
            "SigningKey": "sign_key_888",
            "ClientCert__c": "-----BEGIN CERTIFICATE-----...",
            "Certificate": "-----BEGIN CERTIFICATE-----...",
            "Signature__c": "sig_hex_bytes",
            "Credential_Payload": "cred_blob",
            "CreatedDate": "2026-10-07T12:00:00.000Z",
            "Status": "Active",
        }

        normalized = normalizer.normalize(raw_record)

        # Sensitive secrets must all be masked
        self.assertEqual(normalized["Password"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["User_ClientSecret"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["Security_Token"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["Api_Key"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["AccessToken"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["RefreshToken__c"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["BearerToken"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["AppSecret__c"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["Secret__c"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["EncryptionKey__c"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["SigningKey"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["ClientCert__c"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["Certificate"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["Signature__c"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["Credential_Payload"], "[REDACTED_SECRET]")

        # Non-secret fields must be preserved
        self.assertEqual(normalized["Username"], "admin@example.com")
        self.assertEqual(normalized["Status"], "Active")

    def test_insecure_http_url_rejection(self):
        """Verify plain HTTP is rejected for Salesforce login endpoints."""
        with self.assertRaises(ValueError) as ctx:
            SalesforcePasswordAuth(
                client_id="cid",
                client_secret="sec",
                username="user",
                password="pwd",
                login_url="http://login.salesforce.com",
            )
        self.assertIn("Insecure scheme", str(ctx.exception))

    def test_checkpoint_file_permissions(self):
        """Verify checkpoint state files are saved with strict 0o600 permissions."""
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        try:
            mgr = FileCheckpointManager(filepath=tmp.name)
            mgr.update_checkpoint("test_job", "2026-10-07T12:00:00Z")

            mode = stat.S_IMODE(os.stat(tmp.name).st_mode)
            # Owner read/write only (0o600)
            self.assertEqual(mode, 0o600, f"Expected 0o600 but got {oct(mode)}")
        finally:
            if os.path.exists(tmp.name):
                os.remove(tmp.name)

    def test_permissive_private_key_logs_warning_without_crash(self):
        """Verify that overly permissive private key file triggers a warning and doesn't crash with NameError."""
        import base64
        import logging
        from salesforce_secops.config import AppConfig

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC...\n-----END PRIVATE KEY-----")
            key_path = f.name

        try:
            # Set to permissive permissions (0o644)
            os.chmod(key_path, 0o644)

            env_patch = {
                "CUSTOMER_ID": "test-cust-id",
                "PROJECT_ID": "test-proj-id",
                "SALESFORCE_PRIVATE_KEY_PATH": key_path,
            }
            with unittest.mock.patch.dict(os.environ, env_patch):
                with self.assertLogs("salesforce_secops.config", level="WARNING") as cm:
                    cfg = AppConfig()
                    self.assertTrue(any("SECURITY WARNING: Private key file" in msg for msg in cm.output))
        finally:
            if os.path.exists(key_path):
                os.remove(key_path)

    def test_missing_tenant_id_fails_fast_on_live_ingest(self):
        """Verify SecOps client initialization fails fast if CUSTOMER_ID or PROJECT_ID is omitted for live delivery."""
        from salesforce_secops.config import AppConfig
        from salesforce_secops.sync import init_secops_client

        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            cfg = AppConfig()
            # 1. Direct validation must fail fast
            with self.assertRaises(ValueError) as ctx:
                cfg.validate_secops_config()
            self.assertIn("Refusing to fall back to a default tenant", str(ctx.exception))

            # 2. Live SecOps client initialization must fail fast
            with self.assertRaises(ValueError) as ctx:
                init_secops_client(cfg, dry_run=False)
            self.assertIn("Refusing to fall back to a default tenant", str(ctx.exception))

            # 3. Dry-run must succeed without tenant IDs (does not contact Chronicle)
            client = init_secops_client(cfg, dry_run=True, output_file="/dev/null")
            self.assertIsNotNone(client)

    def test_jwt_claims_include_jti_and_nbf(self):
        """Verify JWT assertion includes jti and nbf claims to prevent replay."""
        import json
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        # Generate a temporary test RSA private key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        auth = SalesforceJWTAuth(
            client_id="test_client_id",
            username="test@example.com",
            private_key=pem,
        )

        jwt_token = auth._create_signed_jwt()
        parts = jwt_token.split(".")
        self.assertEqual(len(parts), 3)

        # Decode payload
        payload_b64 = parts[1]
        padding = "=" * (4 - (len(payload_b64) % 4))
        claims = json.loads(base64.urlsafe_b64decode(payload_b64 + padding).decode("utf-8"))

        self.assertIn("jti", claims)
        self.assertIn("nbf", claims)
        self.assertEqual(claims["iss"], "test_client_id")
        self.assertEqual(claims["sub"], "test@example.com")


if __name__ == "__main__":
    unittest.main()
