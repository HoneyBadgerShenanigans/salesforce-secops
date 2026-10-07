"""State and Checkpoint Management.

Tracks the high-water mark timestamp and record ID for each SOQL query job to enable
reliable incremental polling without gaps or duplicate data ingestion.
Supports:
1. Local File Checkpoint Store
2. Google Cloud Storage (GCS) Checkpoint Store
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class CheckpointManager:
    """Base Checkpoint Manager."""

    def get_checkpoint(self, job_name: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    def update_checkpoint(
        self,
        job_name: str,
        last_timestamp: str,
        last_id: Optional[str] = None,
        records_processed: int = 0,
    ) -> None:
        raise NotImplementedError


class FileCheckpointManager(CheckpointManager):
    """Local JSON file-based checkpoint manager."""

    def __init__(self, filepath: str = ".salesforce_checkpoints.json"):
        self.filepath = filepath
        self._data: Dict[str, Dict[str, Any]] = self._load()

    def _load(self) -> Dict[str, Dict[str, Any]]:
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning("Failed to load checkpoint file %s: %s. Starting fresh.", self.filepath, e)
        return {}

    def _save(self) -> None:
        temp_file = f"{self.filepath}.tmp"
        # Secure file creation with 0o600 permissions (owner read/write only)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(temp_file, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2)
        os.replace(temp_file, self.filepath)
        try:
            os.chmod(self.filepath, 0o600)
        except OSError:
            pass

    def get_checkpoint(self, job_name: str) -> Optional[Dict[str, Any]]:
        return self._data.get(job_name)

    def update_checkpoint(
        self,
        job_name: str,
        last_timestamp: str,
        last_id: Optional[str] = None,
        records_processed: int = 0,
    ) -> None:
        current = self._data.get(job_name, {})
        prev_count = current.get("total_records_processed", 0)
        self._data[job_name] = {
            "last_timestamp": last_timestamp,
            "last_id": last_id,
            "total_records_processed": prev_count + records_processed,
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
        self._save()
        logger.info(
            "Updated checkpoint for '%s': timestamp=%s, id=%s (+%d records)",
            job_name,
            last_timestamp,
            last_id,
            records_processed,
        )


class GCSCheckpointManager(CheckpointManager):
    """Google Cloud Storage (GCS) bucket-based checkpoint manager for serverless runs."""

    def __init__(self, gcs_uri: str):
        # Format: gs://bucket-name/path/to/checkpoint.json
        from google.cloud import storage

        if not gcs_uri.startswith("gs://"):
            raise ValueError(f"Invalid GCS URI: {gcs_uri}")

        parts = gcs_uri[5:].split("/", 1)
        self.bucket_name = parts[0]
        self.blob_path = parts[1] if len(parts) > 1 else "salesforce_checkpoint.json"

        self.storage_client = storage.Client()
        self.bucket = self.storage_client.bucket(self.bucket_name)
        self.blob = self.bucket.blob(self.blob_path)
        self._data: Dict[str, Dict[str, Any]] = self._load()

    def _load(self) -> Dict[str, Dict[str, Any]]:
        if self.blob.exists():
            try:
                content = self.blob.download_as_text()
                return json.loads(content)
            except Exception as e:
                logger.warning("Failed to load GCS checkpoint: %s. Starting fresh.", e)
        return {}

    def _save(self) -> None:
        content = json.dumps(self._data, indent=2)
        self.blob.upload_from_string(content, content_type="application/json")

    def get_checkpoint(self, job_name: str) -> Optional[Dict[str, Any]]:
        return self._data.get(job_name)

    def update_checkpoint(
        self,
        job_name: str,
        last_timestamp: str,
        last_id: Optional[str] = None,
        records_processed: int = 0,
    ) -> None:
        current = self._data.get(job_name, {})
        prev_count = current.get("total_records_processed", 0)
        self._data[job_name] = {
            "last_timestamp": last_timestamp,
            "last_id": last_id,
            "total_records_processed": prev_count + records_processed,
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
        self._save()
        logger.info(
            "Updated GCS checkpoint for '%s': timestamp=%s, id=%s (+%d records)",
            job_name,
            last_timestamp,
            last_id,
            records_processed,
        )
