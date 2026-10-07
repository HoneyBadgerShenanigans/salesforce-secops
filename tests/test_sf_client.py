"""Unit tests for Salesforce SOQL Client."""

import io
import unittest
from unittest.mock import MagicMock, patch

from salesforce_secops.auth import SalesforceAuth
from salesforce_secops.sf_client import SalesforceClient


class DummyAuth(SalesforceAuth):
    def __init__(self):
        super().__init__()
        self._access_token = "dummy_token"
        self._instance_url = "https://example.my.salesforce.com"

    def authenticate(self):
        return {"access_token": self._access_token, "instance_url": self._instance_url}


class TestSalesforceClient(unittest.TestCase):

    def setUp(self):
        self.auth = DummyAuth()
        self.client = SalesforceClient(auth=self.auth)

    def test_prepare_query(self):
        template = "SELECT Id FROM LoginHistory WHERE LoginTime > :checkpoint AND LoginTime < :end_time"
        prepared = SalesforceClient.prepare_query(
            template,
            checkpoint="2026-01-01T00:00:00Z",
            end_time="2026-02-01T00:00:00Z",
        )
        expected = "SELECT Id FROM LoginHistory WHERE LoginTime > 2026-01-01T00:00:00Z AND LoginTime < 2026-02-01T00:00:00Z"
        self.assertEqual(prepared, expected)

    @patch("salesforce_secops.sf_client.requests.request")
    def test_query_rest_pagination(self, mock_req):
        # Page 1
        resp1 = MagicMock()
        resp1.ok = True
        resp1.json.return_value = {
            "totalSize": 2,
            "done": False,
            "nextRecordsUrl": "/services/data/v60.0/query/01gXX000000abc-2000",
            "records": [{"Id": "1", "Status": "Success"}],
        }

        # Page 2
        resp2 = MagicMock()
        resp2.ok = True
        resp2.json.return_value = {
            "totalSize": 2,
            "done": True,
            "nextRecordsUrl": None,
            "records": [{"Id": "2", "Status": "Failed"}],
        }

        mock_req.side_effect = [resp1, resp2]

        results = list(self.client.query_rest("SELECT Id, Status FROM LoginHistory"))
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["Id"], "1")
        self.assertEqual(results[1]["Id"], "2")

    @patch("salesforce_secops.sf_client.requests.request")
    def test_query_bulk(self, mock_req):
        # 1. Job creation
        create_resp = MagicMock()
        create_resp.ok = True
        create_resp.json.return_value = {"id": "750XX000000001", "state": "UploadComplete"}

        # 2. Polling status
        status_resp = MagicMock()
        status_resp.ok = True
        status_resp.json.return_value = {"state": "JobComplete", "numberRecordsProcessed": 2}

        # 3. Job results CSV
        results_resp = MagicMock()
        results_resp.ok = True
        csv_bytes = b"Id,Status,SourceIp\n0Ya1,Success,10.0.0.1\n0Ya2,Failure,10.0.0.2\n"
        results_resp.raw = io.BytesIO(csv_bytes)
        results_resp.headers = {"Sforce-Locator": "null"}

        mock_req.side_effect = [create_resp, status_resp, results_resp]

        records = list(self.client.query_bulk("SELECT Id, Status, SourceIp FROM LoginHistory", poll_interval_seconds=0))
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["Id"], "0Ya1")
        self.assertEqual(records[0]["Status"], "Success")
        self.assertEqual(records[1]["SourceIp"], "10.0.0.2")

    @patch("salesforce_secops.sf_client.requests.request")
    def test_query_bulk_with_embedded_newlines(self, mock_req):
        """Verify that Bulk API streaming correctly parses RFC-4180 CSV containing quoted newlines."""
        create_resp = MagicMock()
        create_resp.ok = True
        create_resp.json.return_value = {"id": "750XX000000002", "state": "UploadComplete"}

        status_resp = MagicMock()
        status_resp.ok = True
        status_resp.json.return_value = {"state": "JobComplete", "numberRecordsProcessed": 2}

        # CSV where row 1 has an embedded newline in a quoted field
        csv_bytes = (
            b'Id,Description,SourceIp\r\n'
            b'0Ya1,"User reported:\nfailed MFA twice",10.0.0.1\r\n'
            b'0Ya2,"Password reset requested\nby manager",10.0.0.2\r\n'
        )
        results_resp = MagicMock()
        results_resp.ok = True
        results_resp.raw = io.BytesIO(csv_bytes)
        results_resp.headers = {"Sforce-Locator": "null"}

        mock_req.side_effect = [create_resp, status_resp, results_resp]

        records = list(self.client.query_bulk("SELECT Id, Description, SourceIp FROM Case", poll_interval_seconds=0))
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["Id"], "0Ya1")
        self.assertEqual(records[0]["Description"], "User reported:\nfailed MFA twice")
        self.assertEqual(records[0]["SourceIp"], "10.0.0.1")
        self.assertEqual(records[1]["Id"], "0Ya2")
        self.assertEqual(records[1]["Description"], "Password reset requested\nby manager")
        self.assertEqual(records[1]["SourceIp"], "10.0.0.2")


if __name__ == "__main__":
    unittest.main()
