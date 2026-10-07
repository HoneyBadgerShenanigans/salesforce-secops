"""Salesforce SOQL Query Client.

Supports:
1. REST Query API with automatic queryMore / cursor pagination
2. Bulk API 2.0 Query for high-volume historical extraction
3. Query placeholder substitution (:checkpoint, :start_time, :end_time)
4. Robust token refresh and transient error retries
"""

import csv
import io
import json
import logging
import re
import time
import urllib.parse
from typing import Any, Dict, Generator, Iterator, List, Optional
import requests

from .auth import SalesforceAuth

logger = logging.getLogger(__name__)

DEFAULT_API_VERSION = "v60.0"


ISO8601_REGEX = re.compile(
    r"^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?$"
)


def validate_timestamp_param(name: str, value: Optional[str]) -> None:
    """Validate that query timestamp parameters strictly follow ISO 8601 format to prevent SOQL injection."""
    if value is not None:
        cleaned = value.strip()
        if not ISO8601_REGEX.match(cleaned):
            raise ValueError(
                f"Security Validation Error: Parameter '{name}' value '{value}' is not a valid ISO 8601 timestamp. "
                "Parameter rejected to prevent SOQL injection."
            )


class SalesforceClient:
    """Client for querying Salesforce using REST API and Bulk API 2.0."""

    def __init__(
        self,
        auth: SalesforceAuth,
        api_version: str = DEFAULT_API_VERSION,
        timeout: int = 60,
    ):
        self.auth = auth
        self.api_version = api_version.lstrip("v")
        self.api_prefix = f"v{self.api_version}"
        self.timeout = timeout
        # Ensure CSV field size limit safely handles large payload fields
        try:
            csv.field_size_limit(10 * 1024 * 1024)
        except Exception:
            pass

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.auth.access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        stream: bool = False,
    ) -> requests.Response:
        """Execute HTTP request with automatic token refresh retry."""
        base_url = self.auth.instance_url.rstrip("/")
        parsed_url = urllib.parse.urlparse(base_url)
        if parsed_url.scheme.lower() != "https":
            raise ValueError(f"Security Error: Insecure scheme in instance URL '{base_url}'. HTTPS is required.")

        url = f"{base_url}/{path.lstrip('/')}"

        for attempt in range(3):
            headers = self._headers()
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=json_data,
                    stream=stream,
                    timeout=self.timeout,
                )
            except requests.RequestException as e:
                if attempt == 2:
                    raise
                logger.warning("Network error contacting Salesforce, retrying: %s", e)
                time.sleep(2 ** attempt)
                continue

            if response.status_code == 401 and attempt < 2:
                logger.info("Session expired or token invalid. Re-authenticating...")
                self.auth.authenticate()
                continue

            if response.status_code == 429:
                # Rate limit encountered
                wait_seconds = 5 * (attempt + 1)
                logger.warning("Salesforce API rate limit hit. Waiting %d seconds...", wait_seconds)
                time.sleep(wait_seconds)
                continue

            if not response.ok:
                raise RuntimeError(
                    f"Salesforce API request failed [{response.status_code} {response.reason}] on {url}: {response.text}"
                )

            return response

        raise RuntimeError(f"Salesforce API request failed after retries: {url}")

    @staticmethod
    def prepare_query(
        query_template: str,
        checkpoint: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> str:
        """Replace placeholders in SOQL query after strict parameter validation.

        Supported placeholders:
        - :checkpoint (ISO 8601 string, e.g. 2026-01-01T00:00:00Z)
        - :start_time
        - :end_time
        """
        # Validate all parameters against SOQL injection
        validate_timestamp_param("checkpoint", checkpoint)
        validate_timestamp_param("start_time", start_time)
        validate_timestamp_param("end_time", end_time)

        query = query_template
        if checkpoint:
            query = query.replace(":checkpoint", checkpoint.strip())
        if start_time:
            query = query.replace(":start_time", start_time.strip())
        if end_time:
            query = query.replace(":end_time", end_time.strip())
        return query.strip()

    def query_rest(
        self,
        soql: str,
        batch_size: int = 2000,
        include_deleted: bool = False,
    ) -> Generator[Dict[str, Any], None, None]:
        """Execute SOQL query using REST API, yielding records one by one.

        Handles pagination via nextRecordsUrl.
        """
        endpoint = "queryAll" if include_deleted else "query"
        path = f"services/data/{self.api_prefix}/{endpoint}"
        params = {"q": soql}

        headers = self._headers()
        # Sforce-Query-Options can request a specific batch size up to 2000
        headers["Sforce-Query-Options"] = f"batchSize={batch_size}"

        logger.info("Executing REST SOQL query: %s", soql)
        response = self._request("GET", path, params=params)
        data = response.json()

        total_size = data.get("totalSize", 0)
        logger.info("REST Query matched %d total records", total_size)

        for record in data.get("records", []):
            yield record

        next_url = data.get("nextRecordsUrl")
        while next_url:
            logger.debug("Fetching next records page: %s", next_url)
            # nextRecordsUrl is formatted like /services/data/vXX.X/query/01g...
            response = self._request("GET", next_url)
            data = response.json()
            for record in data.get("records", []):
                yield record
            next_url = data.get("nextRecordsUrl")

    def query_bulk(
        self,
        soql: str,
        poll_interval_seconds: int = 5,
        max_poll_minutes: int = 60,
    ) -> Generator[Dict[str, Any], None, None]:
        """Execute high-volume SOQL query using Bulk API 2.0.

        Ideal for large historical extractions where REST query might hit timeout limits.
        Yields dictionaries of record rows.
        """
        create_path = f"services/data/{self.api_prefix}/jobs/query"
        payload = {
            "operation": "query",
            "query": soql,
            "contentType": "CSV",
            "columnDelimiter": "COMMA",
            "lineEnding": "LF",
        }

        logger.info("Creating Bulk API 2.0 query job: %s", soql)
        create_resp = self._request("POST", create_path, json_data=payload)
        job_info = create_resp.json()
        job_id = job_info["id"]
        logger.info("Bulk query job created: %s (State: %s)", job_id, job_info.get("state"))

        # Poll until job completes
        status_path = f"services/data/{self.api_prefix}/jobs/query/{job_id}"
        start_poll = time.time()
        timeout_seconds = max_poll_minutes * 60

        while True:
            resp = self._request("GET", status_path)
            status_data = resp.json()
            state = status_data.get("state")
            records_processed = status_data.get("numberRecordsProcessed", 0)

            logger.info(
                "Bulk query job %s state: %s (Records processed: %d)",
                job_id,
                state,
                records_processed,
            )

            if state == "JobComplete":
                break
            if state in ("Failed", "Aborted"):
                err_msg = status_data.get("errorMessage", "Unknown error")
                raise RuntimeError(f"Bulk query job {job_id} {state}: {err_msg}")

            if time.time() - start_poll > timeout_seconds:
                raise TimeoutError(f"Bulk query job {job_id} timed out after {max_poll_minutes} minutes")

            time.sleep(poll_interval_seconds)

        # Retrieve results
        results_path = f"services/data/{self.api_prefix}/jobs/query/{job_id}/results"
        locator: Optional[str] = None

        while True:
            params = {}
            if locator:
                params["locator"] = locator

            results_resp = self._request("GET", results_path, params=params, stream=True)
            # Parse CSV stream
            lines = io.StringIO(results_resp.text)
            reader = csv.DictReader(lines)
            for row in reader:
                yield dict(row)

            # Check next locator in response header
            locator = results_resp.headers.get("Sforce-Locator")
            if not locator or locator == "null":
                break
            logger.debug("Fetching next bulk result chunk with locator: %s", locator)
