"""Unit tests for Checkpoint Manager."""

import os
import tempfile
import unittest
from salesforce_secops.checkpoint import FileCheckpointManager


class TestFileCheckpointManager(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.tmp.close()
        self.mgr = FileCheckpointManager(filepath=self.tmp.name)

    def tearDown(self):
        if os.path.exists(self.tmp.name):
            os.remove(self.tmp.name)

    def test_checkpoint_lifecycle(self):
        # Empty check
        cp = self.mgr.get_checkpoint("login_history")
        self.assertIsNone(cp)

        # Update
        self.mgr.update_checkpoint(
            job_name="login_history",
            last_timestamp="2026-10-07T12:00:00Z",
            last_id="0Ya123456789012345",
            records_processed=150,
        )

        cp = self.mgr.get_checkpoint("login_history")
        self.assertIsNotNone(cp)
        self.assertEqual(cp["last_timestamp"], "2026-10-07T12:00:00Z")
        self.assertEqual(cp["last_id"], "0Ya123456789012345")
        self.assertEqual(cp["total_records_processed"], 150)

        # Update again (cumulative count)
        self.mgr.update_checkpoint(
            job_name="login_history",
            last_timestamp="2026-10-07T13:00:00Z",
            last_id="0Ya999999999999999",
            records_processed=50,
        )

        # Reload manager from same file to test persistence
        mgr2 = FileCheckpointManager(filepath=self.tmp.name)
        cp2 = mgr2.get_checkpoint("login_history")
        self.assertEqual(cp2["last_timestamp"], "2026-10-07T13:00:00Z")
        self.assertEqual(cp2["total_records_processed"], 200)


if __name__ == "__main__":
    unittest.main()
