"""Google SecOps (Chronicle) Ingestion Client.

Supports:
1. Direct Chronicle Ingestion API (batch ingestion into log type SALESFORCE)
2. Google Cloud Storage (GCS) export for Chronicle GCS Feed / Omniflow ingestion
3. Local NDJSON file export (for testing and dry runs)
"""

from datetime import datetime, timezone
import gzip
import io
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional
import google.auth
from google.auth.transport.requests import Request
import requests

logger = logging.getLogger(__name__)

CHRONICLE_SCOPES = [
    "https://www.googleapis.com/auth/chronicle-backlog",
    "https://www.googleapis.com/auth/cloud-platform",
]


class SecOpsIngestionClient:
    """Base client for pushing data to Google SecOps."""

    def ingest_batch(self, logs: List[str], log_type: str = "SALESFORCE") -> int:
        """Ingest a batch of JSON-serialized log strings. Returns count of logs ingested."""
        raise NotImplementedError


class ChronicleApiIngestionClient(SecOpsIngestionClient):
    """Direct Chronicle Ingestion API client."""

    def __init__(
        self,
        customer_id: str,
        project_id: str,
        region: str = "us",
        credentials_path: Optional[str] = None,
    ):
        self.customer_id = customer_id
        self.project_id = project_id
        self.region = region.lower()
        self.credentials_path = credentials_path

        # Obtain GCP credentials
        if self.credentials_path and os.path.exists(self.credentials_path):
            from google.oauth2 import service_account

            self.credentials = service_account.Credentials.from_service_account_file(
                self.credentials_path, scopes=CHRONICLE_SCOPES
            )
        else:
            self.credentials, _ = google.auth.default(scopes=CHRONICLE_SCOPES)

        self.base_url = f"https://chronicle.{self.region}.rep.googleapis.com"

    def _get_auth_header(self) -> Dict[str, str]:
        """Ensure token is fresh and construct authorization header."""
        if not self.credentials.valid:
            self.credentials.refresh(Request())
        return {
            "Authorization": f"Bearer {self.credentials.token}",
            "Content-Type": "application/json",
            "x-goog-user-project": self.project_id,
        }

    def ingest_batch(self, logs: List[str], log_type: str = "SALESFORCE") -> int:
        """Batch ingest logs into Chronicle via the Ingestion API.

        Chronicle API allows batches up to 1,000 entries or ~1 MB.
        """
        if not logs:
            return 0

        # Endpoint for Chronicle Ingestion API batchCreate
        # /v1alpha/projects/{project}/locations/{region}/instances/{customer_id}/logTypes/{log_type}/logs:batchCreate
        endpoint = (
            f"{self.base_url}/v1alpha/projects/{self.project_id}/locations/{self.region}/"
            f"instances/{self.customer_id}/logTypes/{log_type}/logs:batchCreate"
        )

        entries = []
        now_iso = datetime.now(timezone.utc).isoformat()
        for log_str in logs:
            entries.append({
                "log_text": log_str,
                "timestamp": now_iso,
            })

        payload = {"entries": entries}
        headers = self._get_auth_header()

        for attempt in range(3):
            try:
                response = requests.post(endpoint, json=payload, headers=headers, timeout=60)
                if response.ok:
                    logger.info("Successfully ingested batch of %d logs into SecOps (%s)", len(logs), log_type)
                    return len(logs)

                if response.status_code == 401 and attempt < 2:
                    self.credentials.refresh(Request())
                    headers = self._get_auth_header()
                    continue

                logger.warning(
                    "SecOps Ingestion API attempt %d failed [%d]: %s",
                    attempt + 1,
                    response.status_code,
                    response.text,
                )
                time.sleep(2 ** attempt)
            except requests.RequestException as e:
                logger.warning("Network error calling Chronicle Ingestion API: %s", e)
                time.sleep(2 ** attempt)

        raise RuntimeError(f"Failed to ingest batch of {len(logs)} logs into SecOps after 3 attempts.")


class GCSIngestionClient(SecOpsIngestionClient):
    """Ingest via Google Cloud Storage bucket for Google SecOps GCS Feed / Omniflow."""

    def __init__(self, gcs_bucket: str, prefix: str = "salesforce"):
        from google.cloud import storage

        self.bucket_name = gcs_bucket.replace("gs://", "").rstrip("/")
        self.prefix = prefix.strip("/")
        self.storage_client = storage.Client()
        self.bucket = self.storage_client.bucket(self.bucket_name)

    def ingest_batch(self, logs: List[str], log_type: str = "SALESFORCE") -> int:
        """Compress logs and upload as NDJSON to GCS for Chronicle GCS Feed."""
        if not logs:
            return 0

        now = datetime.now(timezone.utc)
        date_partition = now.strftime("%Y-%m-%d")
        timestamp_ms = int(time.time() * 1000)
        blob_name = f"{self.prefix}/{log_type}/{date_partition}/events_{timestamp_ms}.json.gz"

        # Compress NDJSON in memory
        compressed_buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=compressed_buffer, mode="wb") as gz:
            for log_str in logs:
                gz.write((log_str + "\n").encode("utf-8"))

        compressed_data = compressed_buffer.getvalue()
        blob = self.bucket.blob(blob_name)
        blob.upload_from_string(compressed_data, content_type="application/gzip")

        logger.info(
            "Uploaded batch of %d logs to gs://%s/%s (Size: %d bytes)",
            len(logs),
            self.bucket_name,
            blob_name,
            len(compressed_data),
        )
        return len(logs)


class LocalFileIngestionClient(SecOpsIngestionClient):
    """Writes logs to local NDJSON file (useful for dry runs and validation)."""

    def __init__(self, output_path: str = "salesforce_logs.jsonl"):
        self.output_path = output_path

    def ingest_batch(self, logs: List[str], log_type: str = "SALESFORCE") -> int:
        if not logs:
            return 0
        with open(self.output_path, "a", encoding="utf-8") as f:
            for log_str in logs:
                f.write(log_str + "\n")
        logger.info("Wrote %d logs to %s", len(logs), self.output_path)
        return len(logs)
