"""Record Normalizer for Google SecOps (Chronicle) Salesforce Parser.

Transforms raw Salesforce SOQL query records (REST or Bulk) into normalized JSON
events optimized for Google SecOps Chronicle default SALESFORCE parser and UDM mapping.
"""

from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


# Patterns matching sensitive authentication secrets or credentials
SENSITIVE_FIELD_PATTERNS = re.compile(
    r"(?:pass(?:word|wd)|secret|token|key|credential|cert(?:ificate)?|signature)",
    re.IGNORECASE,
)


def _mask_if_sensitive(field_name: str, value: Any) -> Any:
    """Mask value if field name indicates a credential or secret."""
    if value is not None and SENSITIVE_FIELD_PATTERNS.search(field_name):
        return "[REDACTED_SECRET]"
    return value


def _clean_field_name(field: str) -> str:
    """Clean field names, converting dots in flattened fields (e.g. User.Username -> User_Username)."""
    return field.replace(".", "_")


def _format_timestamp(ts_str: Optional[str]) -> Optional[str]:
    """Ensure timestamp is valid ISO 8601 UTC string."""
    if not ts_str:
        return None
    try:
        # Standard Salesforce format: 2026-10-07T14:30:00.000+0000 or 2026-10-07T14:30:00.000Z
        cleaned = ts_str.strip()
        if cleaned.endswith("+0000"):
            cleaned = cleaned[:-5] + "Z"
        elif cleaned.endswith("+00:00"):
            cleaned = cleaned[:-6] + "Z"
        elif not cleaned.endswith("Z") and "+" not in cleaned and "-" not in cleaned[10:]:
            cleaned += "Z"
        return cleaned
    except Exception:
        return ts_str


class SalesforceRecordNormalizer:
    """Normalizes Salesforce SOQL query records for Chronicle ingestion."""

    def __init__(self, instance_url: str = "", default_object: str = ""):
        self.instance_url = instance_url
        self.default_object = default_object

    def normalize(self, record: Dict[str, Any], object_name: Optional[str] = None) -> Dict[str, Any]:
        """Normalize a single Salesforce record dictionary with automatic secret masking."""
        obj = object_name or self.default_object
        normalized: Dict[str, Any] = {}

        # 1. Strip internal Salesforce metadata attribute object
        attrs = record.get("attributes")
        if isinstance(attrs, dict):
            obj = attrs.get("type", obj)

        for key, val in record.items():
            if key == "attributes":
                continue

            # Flatten nested relation objects (e.g. {"User": {"Username": "foo"}} -> {"User_Username": "foo"})
            if isinstance(val, dict):
                sub_attrs = val.get("attributes")
                for sub_key, sub_val in val.items():
                    if sub_key == "attributes":
                        continue
                    clean_nested_key = _clean_field_name(f"{key}_{sub_key}")
                    normalized[clean_nested_key] = _mask_if_sensitive(clean_nested_key, sub_val)
            else:
                clean_k = _clean_field_name(key)
                normalized[clean_k] = _mask_if_sensitive(clean_k, val)

        # 2. Extract or infer primary timestamp for Chronicle
        # Priority order for timestamp determination
        primary_ts: Optional[str] = None
        for ts_candidate in (
            "LoginTime",
            "CreatedDate",
            "EventDate",
            "SystemModstamp",
            "LastModifiedDate",
            "Timestamp",
        ):
            if ts_candidate in normalized and normalized[ts_candidate]:
                primary_ts = _format_timestamp(str(normalized[ts_candidate]))
                break

        if primary_ts:
            normalized["EventDate"] = primary_ts
            # If LoginTime is present, keep it formatted
            if "LoginTime" in normalized:
                normalized["LoginTime"] = _format_timestamp(str(normalized["LoginTime"]))
            if "CreatedDate" in normalized:
                normalized["CreatedDate"] = _format_timestamp(str(normalized["CreatedDate"]))

        # 3. Add SecOps metadata enrichment
        normalized["_salesforce_object"] = obj
        normalized["_instance_url"] = self.instance_url
        normalized["_ingested_at"] = datetime.now(timezone.utc).isoformat()
        normalized["_source"] = "salesforce_soql_integration"

        return normalized

    def to_json_line(self, record: Dict[str, Any], object_name: Optional[str] = None) -> str:
        """Serialize record to newline-delimited JSON string."""
        norm = self.normalize(record, object_name=object_name)
        return json.dumps(norm, separators=(",", ":"))
