"""Security and Vulnerability Defense Tests."""

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
        """Ensure sensitive credentials and auth secrets are automatically masked."""
        normalizer = SalesforceRecordNormalizer(default_object="CustomUserAudit")
        raw_record = {
            "Id": "005123456789012",
            "Username": "admin@example.com",
            "Password": "SuperSecretPassword123!",
            "User_ClientSecret": "cs_live_998877665544",
            "Security_Token": "tok_xyz_secret",
            "Api_Key": "key_abcdef123456",
            "AccessToken": "00D50000000IzUN!AQcAQ...",
            "CreatedDate": "2026-10-07T12:00:00.000Z",
        }

        normalized = normalizer.normalize(raw_record)

        self.assertEqual(normalized["Password"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["User_ClientSecret"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["Security_Token"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["Api_Key"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["AccessToken"], "[REDACTED_SECRET]")
        self.assertEqual(normalized["Username"], "admin@example.com")

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


if __name__ == "__main__":
    unittest.main()
