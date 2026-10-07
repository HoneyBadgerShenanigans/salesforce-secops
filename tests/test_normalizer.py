"""Unit tests for Salesforce Record Normalizer."""

import unittest
from salesforce_secops.normalizer import SalesforceRecordNormalizer


class TestSalesforceRecordNormalizer(unittest.TestCase):

    def setUp(self):
        self.normalizer = SalesforceRecordNormalizer(
            instance_url="https://testorg.my.salesforce.com",
            default_object="LoginHistory",
        )

    def test_strip_attributes_and_flatten_nested(self):
        raw_record = {
            "attributes": {"type": "LoginHistory", "url": "/services/data/v60.0/sobjects/LoginHistory/0Ya..."},
            "Id": "0Ya123456789012345",
            "LoginTime": "2026-10-07T14:30:00.000+0000",
            "UserId": "005123456789012345",
            "SourceIp": "198.51.100.24",
            "Status": "Success",
            "User": {
                "attributes": {"type": "User"},
                "Username": "admin@example.com",
                "Email": "admin@example.com",
            },
        }

        norm = self.normalizer.normalize(raw_record)

        self.assertNotIn("attributes", norm)
        self.assertEqual(norm["Id"], "0Ya123456789012345")
        self.assertEqual(norm["SourceIp"], "198.51.100.24")
        self.assertEqual(norm["Status"], "Success")
        self.assertEqual(norm["User_Username"], "admin@example.com")
        self.assertEqual(norm["User_Email"], "admin@example.com")
        self.assertEqual(norm["LoginTime"], "2026-10-07T14:30:00.000Z")
        self.assertEqual(norm["EventDate"], "2026-10-07T14:30:00.000Z")
        self.assertEqual(norm["_salesforce_object"], "LoginHistory")
        self.assertEqual(norm["_instance_url"], "https://testorg.my.salesforce.com")

    def test_flatten_bulk_dotted_keys(self):
        bulk_row = {
            "Id": "0Ya111111111111111",
            "LoginTime": "2026-05-01T10:00:00Z",
            "User.Username": "secops@example.com",
            "User.Profile.Name": "System Administrator",
        }

        norm = self.normalizer.normalize(bulk_row, object_name="LoginHistory")
        self.assertEqual(norm["User_Username"], "secops@example.com")
        self.assertEqual(norm["User_Profile_Name"], "System Administrator")
        self.assertEqual(norm["EventDate"], "2026-05-01T10:00:00Z")


if __name__ == "__main__":
    unittest.main()
