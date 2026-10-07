"""Configuration Loader for Salesforce to Google SecOps Integration."""

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional
import yaml
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Automatically load environment variables from .env if present
load_dotenv()


def load_yaml(file_path: str) -> Dict[str, Any]:
    """Safely load a YAML configuration file."""
    p = Path(file_path)
    if not p.exists():
        return {}
    with open(p, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


class AppConfig:
    """Consolidated configuration parser combining YAML and environment variables."""

    def __init__(self, config_path: Optional[str] = None):
        self.raw_config = load_yaml(config_path) if config_path else {}
        sf = self.raw_config.get("salesforce", {})
        secops = self.raw_config.get("secops", {})

        # Salesforce parameters
        self.sf_auth_type = os.getenv("SALESFORCE_AUTH_TYPE", sf.get("auth_type", "jwt"))
        self.sf_login_url = os.getenv("SALESFORCE_LOGIN_URL", sf.get("login_url", "https://login.salesforce.com"))
        self.sf_client_id = os.getenv("SALESFORCE_CLIENT_ID", sf.get("client_id", ""))
        self.sf_username = os.getenv("SALESFORCE_USERNAME", sf.get("username", ""))

        # Private key for JWT
        key_path = os.getenv("SALESFORCE_PRIVATE_KEY_PATH", sf.get("private_key_path", ""))
        if key_path and os.path.exists(key_path):
            try:
                st = os.stat(key_path)
                # Check if group or others have read/write access (e.g. 0644, 0666, 0777)
                if st.st_mode & 0o077:
                    logging.getLogger(__name__).warning(
                        "SECURITY WARNING: Private key file '%s' has overly permissive file mode (%o). "
                        "Permissions should be restricted using 'chmod 600 %s'.",
                        key_path,
                        st.st_mode & 0o777,
                        key_path,
                    )
            except OSError:
                pass

            with open(key_path, "r", encoding="utf-8") as f:
                self.sf_private_key = f.read()
        else:
            self.sf_private_key = os.getenv("SALESFORCE_PRIVATE_KEY", sf.get("private_key", ""))

        # Password auth fallback
        self.sf_client_secret = os.getenv("SALESFORCE_CLIENT_SECRET", sf.get("client_secret", ""))
        self.sf_password = os.getenv("SALESFORCE_PASSWORD", sf.get("password", ""))
        self.sf_security_token = os.getenv("SALESFORCE_SECURITY_TOKEN", sf.get("security_token", ""))

        self.sf_api_version = os.getenv("SALESFORCE_API_VERSION", sf.get("api_version", "v60.0"))

        # Google SecOps parameters
        self.secops_delivery = os.getenv("SECOPS_DELIVERY", secops.get("delivery", "api"))
        self.secops_customer_id = (
            os.getenv("CUSTOMER_ID")
            or os.getenv("SECOPS_CUSTOMER_ID")
            or secops.get("customer_id", "")
        )
        self.secops_project_id = (
            os.getenv("PROJECT_ID")
            or os.getenv("SECOPS_PROJECT_ID")
            or secops.get("project_id", "")
        )

        self.secops_region = os.getenv(
            "REGION",
            os.getenv("SECOPS_REGION", secops.get("region", "us")),
        )
        self.secops_credentials_path = os.getenv(
            "GOOGLE_APPLICATION_CREDENTIALS",
            secops.get("credentials_path", ""),
        )
        self.secops_log_type = os.getenv("SECOPS_LOG_TYPE", secops.get("log_type", "SALESFORCE"))
        self.gcs_bucket = os.getenv("SECOPS_GCS_BUCKET", secops.get("gcs_bucket", ""))
        self.gcs_prefix = os.getenv("SECOPS_GCS_PREFIX", secops.get("gcs_prefix", "salesforce"))

        # Checkpoint parameters
        checkpoints = self.raw_config.get("checkpoint", {})
        self.checkpoint_backend = os.getenv(
            "CHECKPOINT_BACKEND", checkpoints.get("backend", "file")
        )
        self.checkpoint_path = os.getenv(
            "CHECKPOINT_PATH", checkpoints.get("path", ".salesforce_checkpoints.json")
        )

        # Batching & execution
        exec_cfg = self.raw_config.get("execution", {})
        self.batch_size = int(os.getenv("BATCH_SIZE", exec_cfg.get("batch_size", 1000)))
        self.use_bulk_api = os.getenv(
            "USE_BULK_API", str(exec_cfg.get("use_bulk_api", False))
        ).lower() in ("true", "1", "yes")

        # Queries
        default_queries_path = Path(__file__).parent / "queries.yaml"
        self.queries = load_yaml(str(default_queries_path)).get("queries", {})
        if "queries" in self.raw_config:
            self.queries.update(self.raw_config["queries"])

    def validate_secops_config(self) -> None:
        """Validate that mandatory Google SecOps tenant parameters are present for live delivery."""
        if self.secops_delivery.lower() == "api":
            if not self.secops_customer_id:
                raise ValueError(
                    "Configuration Error: 'customer_id' (or CUSTOMER_ID env var) is required for Chronicle API ingestion. "
                    "Refusing to fall back to a default tenant to prevent cross-tenant data disclosure."
                )
            if not self.secops_project_id:
                raise ValueError(
                    "Configuration Error: 'project_id' (or PROJECT_ID env var) is required for Chronicle API ingestion. "
                    "Refusing to fall back to a default project."
                )
        elif self.secops_delivery.lower() == "gcs":
            if not self.gcs_bucket:
                raise ValueError(
                    "Configuration Error: 'gcs_bucket' (or SECOPS_GCS_BUCKET env var) is required for GCS delivery."
                )
