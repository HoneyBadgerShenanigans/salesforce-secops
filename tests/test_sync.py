"""Unit tests for SyncEngine orchestration."""

import tempfile
import unittest
from unittest.mock import MagicMock, patch

from salesforce_secops.checkpoint import FileCheckpointManager
from salesforce_secops.config import AppConfig
from salesforce_secops.secops_client import LocalFileIngestionClient
from salesforce_secops.sf_client import SalesforceClient
from salesforce_secops.sync import SyncEngine


class DummyAuth:
    access_token = "mock_token"
    instance_url = "https://org.salesforce.com"


class TestSyncEngine(unittest.TestCase):

    def setUp(self):
        self.tmp_out = tempfile.NamedTemporaryFile(delete=False)
        self.tmp_cp = tempfile.NamedTemporaryFile(delete=False)
        self.tmp_out.close()
        self.tmp_cp.close()

        self.config = AppConfig()
        self.config.batch_size = 10
        self.config.secops_log_type = "SALESFORCE"

        self.sf_client = SalesforceClient(auth=DummyAuth())
        self.secops_client = LocalFileIngestionClient(output_path=self.tmp_out.name)
        self.checkpoint_mgr = FileCheckpointManager(filepath=self.tmp_cp.name)

        self.engine = SyncEngine(
            config=self.config,
            sf_client=self.sf_client,
            secops_client=self.secops_client,
            checkpoint_mgr=self.checkpoint_mgr,
        )

    def test_run_query_task_incremental(self):
        query_def = {
            "object": "LoginHistory",
            "timestamp_field": "LoginTime",
            "id_field": "Id",
            "soql": "SELECT Id, LoginTime, Status FROM LoginHistory WHERE LoginTime > :checkpoint",
        }

        mock_records = [
            {"Id": "0Ya1", "LoginTime": "2026-10-07T10:00:00.000Z", "Status": "Success"},
            {"Id": "0Ya2", "LoginTime": "2026-10-07T11:00:00.000Z", "Status": "Success"},
        ]

        with patch.object(self.sf_client, "query_rest", return_value=iter(mock_records)):
            ingested = self.engine.run_query_task("login_history", query_def, is_backfill=False)
            self.assertEqual(ingested, 2)

        # Checkpoint should have been updated
        cp = self.checkpoint_mgr.get_checkpoint("login_history")
        self.assertIsNotNone(cp)
        self.assertEqual(cp["last_timestamp"], "2026-10-07T11:00:00.000Z")
        self.assertEqual(cp["last_id"], "0Ya2")
        self.assertEqual(cp["total_records_processed"], 2)


if __name__ == "__main__":
    unittest.main()
