"""Main Synchronization and Execution Engine for Salesforce to Google SecOps.

Supports:
- Incremental extraction using high-water mark checkpoints
- Historical backfills across custom date intervals
- Bulk API 2.0 and REST SOQL execution
- Seamless ingestion into Chronicle SIEM or GCS Omniflow bucket
"""

import argparse
from datetime import datetime, timedelta, timezone
import json
import logging
import sys
from typing import Any, Dict, List, Optional

from .auth import SalesforceJWTAuth, SalesforcePasswordAuth
from .checkpoint import CheckpointManager, FileCheckpointManager, GCSCheckpointManager
from .config import AppConfig
from .normalizer import SalesforceRecordNormalizer
from .secops_client import (
    ChronicleApiIngestionClient,
    GCSIngestionClient,
    LocalFileIngestionClient,
    SecOpsIngestionClient,
)
from .sf_client import SalesforceClient, validate_timestamp_param

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("salesforce_secops_sync")


def init_salesforce_client(config: AppConfig) -> SalesforceClient:
    """Initialize Salesforce Client based on auth type."""
    if config.sf_auth_type.lower() == "jwt":
        if not config.sf_client_id or not config.sf_username or not config.sf_private_key:
            raise ValueError(
                "JWT auth requires SALESFORCE_CLIENT_ID, SALESFORCE_USERNAME, and SALESFORCE_PRIVATE_KEY."
            )
        auth = SalesforceJWTAuth(
            client_id=config.sf_client_id,
            username=config.sf_username,
            private_key=config.sf_private_key,
            login_url=config.sf_login_url,
        )
    elif config.sf_auth_type.lower() == "password":
        auth = SalesforcePasswordAuth(
            client_id=config.sf_client_id,
            client_secret=config.sf_client_secret,
            username=config.sf_username,
            password=config.sf_password,
            security_token=config.sf_security_token,
            login_url=config.sf_login_url,
        )
    else:
        raise ValueError(f"Unsupported auth type: {config.sf_auth_type}")

    return SalesforceClient(auth=auth, api_version=config.sf_api_version)


def init_secops_client(config: AppConfig, dry_run: bool = False, output_file: Optional[str] = None) -> SecOpsIngestionClient:
    """Initialize Google SecOps Ingestion Client."""
    if dry_run or output_file:
        out_path = output_file or "salesforce_secops_dry_run.jsonl"
        return LocalFileIngestionClient(output_path=out_path)

    if config.secops_delivery.lower() == "gcs":
        if not config.gcs_bucket:
            raise ValueError("GCS delivery requires SECOPS_GCS_BUCKET.")
        return GCSIngestionClient(gcs_bucket=config.gcs_bucket, prefix=config.gcs_prefix)

    return ChronicleApiIngestionClient(
        customer_id=config.secops_customer_id,
        project_id=config.secops_project_id,
        region=config.secops_region,
        credentials_path=config.secops_credentials_path if config.secops_credentials_path else None,
    )


def init_checkpoint_manager(config: AppConfig) -> CheckpointManager:
    """Initialize Checkpoint Manager."""
    if config.checkpoint_backend.lower() == "gcs":
        return GCSCheckpointManager(gcs_uri=config.checkpoint_path)
    return FileCheckpointManager(filepath=config.checkpoint_path)


class SyncEngine:
    """Orchestrates pulling from Salesforce and pushing into Google SecOps."""

    def __init__(
        self,
        config: AppConfig,
        sf_client: SalesforceClient,
        secops_client: SecOpsIngestionClient,
        checkpoint_mgr: CheckpointManager,
    ):
        self.config = config
        self.sf_client = sf_client
        self.secops_client = secops_client
        self.checkpoint_mgr = checkpoint_mgr
        self.normalizer = SalesforceRecordNormalizer(
            instance_url=sf_client.auth.instance_url
        )

    def run_query_task(
        self,
        task_name: str,
        query_def: Dict[str, Any],
        is_backfill: bool = False,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        use_bulk: Optional[bool] = None,
    ) -> int:
        """Execute a single query extraction and ingestion pipeline."""
        object_name = query_def.get("object", "UnknownObject")
        ts_field = query_def.get("timestamp_field", "CreatedDate")
        id_field = query_def.get("id_field", "Id")
        soql_template = query_def["soql"]
        use_bulk_api = use_bulk if use_bulk is not None else self.config.use_bulk_api

        # Determine checkpoint / time range
        checkpoint_val: Optional[str] = None
        if is_backfill:
            if not start_time:
                raise ValueError("Backfill mode requires start_time")
            effective_start = start_time
            effective_end = end_time or datetime.now(timezone.utc).isoformat()
            checkpoint_val = effective_start
        else:
            cp_data = self.checkpoint_mgr.get_checkpoint(task_name)
            if cp_data and cp_data.get("last_timestamp"):
                checkpoint_val = cp_data["last_timestamp"]
            else:
                lookback_days = query_def.get("default_lookback_days", 7)
                start_dt = datetime.now(timezone.utc) - timedelta(days=lookback_days)
                checkpoint_val = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

            effective_start = checkpoint_val
            effective_end = end_time or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        formatted_query = SalesforceClient.prepare_query(
            soql_template,
            checkpoint=checkpoint_val,
            start_time=effective_start,
            end_time=effective_end,
        )

        logger.info(
            "Starting task '%s' [%s] (Bulk: %s) Range: %s -> %s",
            task_name,
            object_name,
            use_bulk_api,
            effective_start,
            effective_end,
        )

        if use_bulk_api:
            record_stream = self.sf_client.query_bulk(formatted_query)
        else:
            record_stream = self.sf_client.query_rest(formatted_query, batch_size=2000)

        batch_logs: List[str] = []
        total_ingested = 0
        latest_ts = checkpoint_val
        latest_id: Optional[str] = None

        for record in record_stream:
            # Track high-water mark timestamp (validate to prevent checkpoint poisoning)
            rec_ts = record.get(ts_field)
            if rec_ts:
                ts_str = str(rec_ts).strip()
                try:
                    validate_timestamp_param(ts_field, ts_str)
                    latest_ts = ts_str
                except ValueError as err:
                    logger.warning(
                        "Skipping malformed timestamp '%s' in record %s: %s",
                        ts_str,
                        record.get(id_field, "unknown"),
                        err,
                    )
            if id_field in record:
                latest_id = str(record[id_field])

            json_line = self.normalizer.to_json_line(record, object_name=object_name)
            batch_logs.append(json_line)

            if len(batch_logs) >= self.config.batch_size:
                count = self.secops_client.ingest_batch(
                    batch_logs, log_type=self.config.secops_log_type
                )
                total_ingested += count
                batch_logs = []

        if batch_logs:
            count = self.secops_client.ingest_batch(
                batch_logs, log_type=self.config.secops_log_type
            )
            total_ingested += count

        logger.info(
            "Task '%s' completed. Total records processed: %d. High-water timestamp: %s",
            task_name,
            total_ingested,
            latest_ts,
        )

        # Update checkpoint only during incremental runs or forward sync
        if not is_backfill and total_ingested > 0 and latest_ts:
            self.checkpoint_mgr.update_checkpoint(
                job_name=task_name,
                last_timestamp=latest_ts,
                last_id=latest_id,
                records_processed=total_ingested,
            )

        return total_ingested


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract arbitrary historical or incremental data from Salesforce into Google SecOps (Chronicle)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: test-connection
    subparsers.add_parser("test-connection", help="Validate authentication and connection to Salesforce")

    # Subcommand: poll (incremental)
    poll_parser = subparsers.add_parser("poll", help="Run incremental query polling using checkpoints")
    poll_parser.add_argument("--config", "-c", help="Path to custom config YAML")
    poll_parser.add_argument("--query", "-q", help="Specific query name to execute (default: all)")
    poll_parser.add_argument("--bulk", action="store_true", help="Force Bulk API 2.0 query")
    poll_parser.add_argument("--dry-run", action="store_true", help="Do not send to SecOps; dump to local file")
    poll_parser.add_argument("--output", "-o", help="Output file path for dry-run")

    # Subcommand: backfill (historical)
    bf_parser = subparsers.add_parser("backfill", help="Extract historical data range via custom SOQL")
    bf_parser.add_argument("--config", "-c", help="Path to custom config YAML")
    bf_parser.add_argument("--query", "-q", help="Query name from queries.yaml or custom")
    bf_parser.add_argument("--soql", help="Direct custom SOQL query string with :start_time and :end_time")
    bf_parser.add_argument("--object", default="CustomObject", help="Salesforce object name for parser tag")
    bf_parser.add_argument("--start-time", required=True, help="Start ISO timestamp (e.g. 2025-01-01T00:00:00Z)")
    bf_parser.add_argument("--end-time", help="End ISO timestamp (default: now)")
    bf_parser.add_argument("--bulk", action="store_true", help="Use Bulk API 2.0 (recommended for large backfills)")
    bf_parser.add_argument("--dry-run", action="store_true", help="Do not send to SecOps; dump to local file")
    bf_parser.add_argument("--output", "-o", help="Output file path for dry-run")

    return parser.parse_args()


def main():
    args = parse_args()
    config_path = getattr(args, "config", None)
    config = AppConfig(config_path=config_path)

    if args.command == "test-connection":
        sf_client = init_salesforce_client(config)
        logger.info("Attempting to connect to Salesforce instance...")
        token = sf_client.auth.access_token
        logger.info("Successfully authenticated! Instance URL: %s", sf_client.auth.instance_url)
        # Test basic query
        res = list(sf_client.query_rest("SELECT Id, Name FROM Organization LIMIT 1"))
        logger.info("Connection test successful! Organization record: %s", res)
        sys.exit(0)

    dry_run = getattr(args, "dry_run", False)
    output_file = getattr(args, "output", None)
    sf_client = init_salesforce_client(config)
    secops_client = init_secops_client(config, dry_run=dry_run, output_file=output_file)
    checkpoint_mgr = init_checkpoint_manager(config)

    engine = SyncEngine(
        config=config,
        sf_client=sf_client,
        secops_client=secops_client,
        checkpoint_mgr=checkpoint_mgr,
    )

    if args.command == "poll":
        target_queries = (
            {args.query: config.queries[args.query]}
            if args.query and args.query in config.queries
            else config.queries
        )
        if not target_queries:
            logger.error("No valid queries found to execute.")
            sys.exit(1)

        total_all = 0
        for q_name, q_def in target_queries.items():
            total_all += engine.run_query_task(
                task_name=q_name,
                query_def=q_def,
                is_backfill=False,
                use_bulk=args.bulk if args.bulk else None,
            )
        logger.info("Poll synchronization complete. Total logs ingested: %d", total_all)

    elif args.command == "backfill":
        if args.soql:
            q_def = {
                "object": args.object,
                "soql": args.soql,
                "timestamp_field": "CreatedDate",
            }
            task_name = f"custom_backfill_{args.object}"
        elif args.query and args.query in config.queries:
            q_def = config.queries[args.query]
            task_name = f"backfill_{args.query}"
        else:
            logger.error("Must provide either a registered --query name or custom --soql")
            sys.exit(1)

        total = engine.run_query_task(
            task_name=task_name,
            query_def=q_def,
            is_backfill=True,
            start_time=args.start_time,
            end_time=args.end_time,
            use_bulk=args.bulk if args.bulk else True,
        )
        logger.info("Backfill complete. Total logs extracted and ingested: %d", total)


if __name__ == "__main__":
    main()
