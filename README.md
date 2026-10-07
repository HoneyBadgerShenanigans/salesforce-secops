# Salesforce Custom SOQL to Google SecOps (Chronicle) Integration

A robust, enterprise-grade integration that extracts **arbitrary historical data and security logs via custom SOQL queries** from Salesforce and delivers them directly into **Google SecOps (Chronicle SIEM)**.

---

## 1. Problem Statement & Architecture

### Why This Integration Is Needed
The native Google SecOps "Third Party API" feed for Salesforce is strictly coupled to the **Salesforce EventLogFile API** (Event Monitoring). This imposes several operational limitations:
* **No Arbitrary SOQL Extraction**: You cannot execute arbitrary SOQL queries to extract standard objects like `LoginHistory`, `SetupAuditTrail`, `LoginGeo`, `AuthSession`, or custom objects.
* **No Ad-Hoc Historical Backfills**: The native feed only streams forward-looking or recent hourly/daily `EventLogFile` files (retained for only 24 hours to 30 days depending on the Salesforce edition).
* **Licensing Requirement**: `EventLogFile` requires the expensive Salesforce Shield / Event Monitoring add-on license. Organizations running standard Salesforce Enterprise or Unlimited editions can only access `LoginHistory` and `SetupAuditTrail` via SOQL queries.

### Comparison: Splunk App 5930 vs Native SecOps Feed vs This Integration

| Feature | Native SecOps Feed | Splunk App (5930) | **This Custom Integration** |
| :--- | :---: | :---: | :---: |
| **Salesforce Source** | `EventLogFile` only | Custom SOQL & Objects | **Any Salesforce Object via SOQL** |
| **Historical Backfills** | ❌ None (only forward-looking) | ✅ Yes (timestamp bounds) | ✅ **Yes (REST & Bulk API 2.0)** |
| **High-Volume Queries** | ❌ Restricted to files | ⚠️ Limited by REST query timeouts | ✅ **Bulk API 2.0 (Millions of records)** |
| **Incremental Checkpoints** | Handled internally | Supported | ✅ **High-water mark (File / GCS)** |
| **Chronicle UDM Mapping** | Built-in | N/A (Splunk sourcetypes) | ✅ **100% compatible with Chronicle default parser** |
| **Delivery Options** | Native feed | Splunk HEC / Forwarder | ✅ **Direct Chronicle Ingestion API or GCS Feed** |

---

## 2. Key Capabilities

1. **Arbitrary SOQL Queries**: Run queries against any standard or custom Salesforce object.
2. **Bulk API 2.0 & REST Support**:
   - **REST Query API**: Automatic `nextRecordsUrl` cursor pagination for near-real-time polling.
   - **Bulk API 2.0**: Asynchronous streaming for multi-month or multi-million-record historical backfills without timing out or exceeding governor limits.
3. **Chronicle Default Parser Compatibility**: Formats records to seamlessly trigger Google SecOps' default `SALESFORCE` parser and populate UDM fields (`metadata.event_timestamp`, `principal.ip`, `principal.user.userid`, `security_result.action`, etc.).
4. **State & Checkpoint Management**: Tracks query high-water marks (`:checkpoint`) to ensure no gaps and no duplicate events across runs. Supports local JSON or Google Cloud Storage state files.
5. **Pre-configured Security Queries**: Out-of-the-box configurations for:
   - `LoginHistory` (authentication outcomes, source IPs, TLS ciphers, client platforms)
   - `SetupAuditTrail` (administrative changes, privilege escalations, permission set delegations)
   - `AuthSession` (active user sessions, session security levels)
   - `LoginGeo` (IP geolocation, city, country, ISP)
   - `PermissionSetAssignment` (privilege and permission changes)

---

## 3. Directory Layout

```
salesforce_secops/
├── __init__.py
├── auth.py                  # OAuth 2.0 JWT Bearer (RFC 7523) & Password auth
├── sf_client.py             # REST & Bulk API 2.0 SOQL extraction client
├── secops_client.py         # Chronicle Ingestion API & GCS Feed writer
├── normalizer.py            # Converts SOQL rows into Chronicle UDM-ready JSON
├── checkpoint.py            # High-water mark state manager (local / GCS)
├── config.py                # YAML + Environment variable configuration loader
├── queries.yaml             # Pre-configured SOQL security queries
├── sync.py                  # CLI orchestration runner (poll, backfill, dry-run)
├── config.example.yaml      # Configuration template
├── requirements.txt         # Direct dependency specifications
├── requirements.lock        # Sha256 hash-pinned hermetic lockfile
├── Dockerfile               # Multi-arch digest-pinned container build
├── deploy_cloud_run.sh      # Automated least-privilege Cloud Run deployment
└── tests/                   # Full unit and security test suite (19/19 tests passing)
```

---

## 4. Setup & Prerequisites

### Step 1: Salesforce Connected App Setup
1. In Salesforce Setup, create an **External Client App** or **Connected App**:
   - Enable **OAuth Settings**.
   - Check **Use digital signatures** and upload your public certificate (`salesforce_cert.crt`).
   - Selected OAuth Scopes: `Manage user data via APIs (api)`, `Perform requests at any time (refresh_token, offline_access)`.
2. Generate an RSA Keypair if you haven't already:
   ```bash
   # Generate private key in PKCS#8 format
   openssl genpkey -algorithm RSA -out salesforce_private.key -pkeyopt rsa_keygen_bits:2048
   # Generate public certificate
   openssl req -new -x509 -key salesforce_private.key -out salesforce_cert.crt -days 365
   ```
3. Pre-authorize the integration user or profile under **Manage Connected Apps > Permitted Users** -> select *Admin approved users are pre-authorized*.
4. Note your **Consumer Key** (`client_id`) and integration **Username**.

### Step 2: Google SecOps (Chronicle) Permissions
Ensure your GCP identity or Service Account has:
- `roles/chronicle.admin` or `roles/chronicle.editor` / `Chronicle Ingestion API` access.
- Target Tenant Details:
  - **Project ID**: `YOUR_GCP_PROJECT_ID`
  - **Customer ID**: `YOUR_CHRONICLE_CUSTOMER_ID`
  - **Region**: `us` (or `europe`, `asia-southeast1`)
  - **Log Type**: `SALESFORCE`

---

## 5. Usage Guide

### Test Connection
Verify Salesforce credentials and network connectivity:
```bash
python3 -m salesforce_secops.sync test-connection
```

### Dry Run (Validate Output Locally)
Extract 10 records and inspect the parsed Chronicle-ready JSON output without pushing to Google SecOps:
```bash
python3 -m salesforce_secops.sync poll \
  --query login_history \
  --dry-run \
  --output ./dry_run_login_history.jsonl
```

### Incremental Polling (Scheduled Sync)
Poll all configured queries incrementally. The high-water mark timestamp is automatically recorded:
```bash
# Poll all security queries in queries.yaml
python3 -m salesforce_secops.sync poll

# Or poll only SetupAuditTrail
python3 -m salesforce_secops.sync poll --query setup_audit_trail
```

### Historical Backfill (Custom Date Range)
Extract 1 year of historical `LoginHistory` using Salesforce Bulk API 2.0 and stream directly to Google SecOps:
```bash
python3 -m salesforce_secops.sync backfill \
  --query login_history \
  --start-time "2025-01-01T00:00:00Z" \
  --end-time "2026-01-01T00:00:00Z" \
  --bulk
```

### Arbitrary Custom SOQL Backfill
Execute any custom query with `:start_time` and `:end_time` placeholders:
```bash
python3 -m salesforce_secops.sync backfill \
  --object "SensitiveRecordAccess" \
  --soql "SELECT Id, UserId, RecordId, Action, CreatedDate FROM CustomAudit__c WHERE CreatedDate >= :start_time AND CreatedDate < :end_time ORDER BY CreatedDate ASC" \
  --start-time "2025-06-01T00:00:00Z" \
  --end-time "2025-12-31T23:59:59Z" \
  --bulk
```

---

---

## 6. Deployment Patterns

### Option A: Cloud Run Jobs + Cloud Scheduler (Recommended Serverless Pattern)

**Why Cloud Run Jobs?**
* **Zero Idle Cost**: Unlike a standard Cloud Run Service that waits for HTTP requests, a **Job** executes on a schedule, pulls Salesforce data, pushes to SecOps, updates the GCS checkpoint, and immediately scales to zero.
* **Serverless Checkpointing**: State is persisted across runs in Google Cloud Storage via `CHECKPOINT_BACKEND=gcs`.
* **Zero Static GCP Keys**: Leverages Google Cloud Application Default Credentials (ADC) via Cloud Run's attached Service Account.
* **Secure Secrets**: Salesforce private keys and client IDs are loaded directly from Google Cloud Secret Manager.

#### Step-by-Step Cloud Run Deployment:

1. **Store Secrets in Secret Manager**:
   ```bash
   gcloud secrets create salesforce-client-id --data-file=- <<< "YOUR_CLIENT_ID"
   gcloud secrets create salesforce-username --data-file=- <<< "secops@yourcompany.com"
   gcloud secrets create salesforce-private-key --data-file=./salesforce_private.key
   ```

2. **Automated Deploy via Script**:
   Run the deployment automation script:
   ```bash
   PROJECT_ID="YOUR_GCP_PROJECT_ID" CUSTOMER_ID="YOUR_CHRONICLE_CUSTOMER_ID" ./deploy_cloud_run.sh
   ```
   Or manually build and deploy:
   ```bash
   # Build container image
   gcloud builds submit --tag us-central1-docker.pkg.dev/YOUR_GCP_PROJECT_ID/secops-integrations/salesforce-secops:v1.0.0

   # Deploy Job
   gcloud run jobs deploy salesforce-secops-sync \
     --image=us-central1-docker.pkg.dev/YOUR_GCP_PROJECT_ID/secops-integrations/salesforce-secops:v1.0.0 \
     --region=us-central1 \
     --project=YOUR_GCP_PROJECT_ID \
     --set-env-vars="CUSTOMER_ID=YOUR_CHRONICLE_CUSTOMER_ID,PROJECT_ID=YOUR_GCP_PROJECT_ID,REGION=us,CHECKPOINT_BACKEND=gcs,CHECKPOINT_PATH=gs://YOUR_GCP_PROJECT_ID-secops-state/checkpoints/salesforce_state.json,SALESFORCE_AUTH_TYPE=jwt" \
     --set-secrets="SALESFORCE_CLIENT_ID=salesforce-client-id:latest,SALESFORCE_USERNAME=salesforce-username:latest,SALESFORCE_PRIVATE_KEY=salesforce-private-key:latest" \
     --max-retries=1 \
     --task-timeout=600s

   # Schedule to run every 10 minutes
   gcloud scheduler jobs create http salesforce-secops-scheduler \
     --location=us-central1 \
     --schedule="*/10 * * * *" \
     --uri="https://us-central1-run.googleapis.com/v2/projects/YOUR_GCP_PROJECT_ID/locations/us-central1/jobs/salesforce-secops-sync:run" \
     --http-method=POST \
     --oauth-service-account-email=salesforce-secops-runner@YOUR_GCP_PROJECT_ID.iam.gserviceaccount.com
   ```

### Option B: High-Volume GCS Omniflow Pipeline
For organizations extracting dozens of gigabytes of historical data:
1. Set `SECOPS_DELIVERY=gcs` and `SECOPS_GCS_BUCKET=gs://my-chronicle-staging-bucket`.
2. Configure a native **Google SecOps Cloud Storage Feed (Omniflow V2)** targeting `gs://my-chronicle-staging-bucket/salesforce/SALESFORCE/` with Log Type `SALESFORCE`.
3. The sync script compresses and streams NDJSON directly into GCS, and Chronicle's Omniflow STS pipeline ingests it with zero API quota constraints.

---

## 7. Security Considerations & Data Protection

* **Credential Redaction Scope**: The normalizer automatically redacts values for fields matching common secret naming patterns (`*Password*`, `*Token*`, `*Secret*`, `*Key*`, `*Cert*`). It does **not** perform content-based DLP inspection on unstructured free-text fields (such as `Description__c`, `ChatterPost`, or `Comments`). Custom SOQL queries should select only fields necessary for security analysis.
* **IAM Least Privilege**: Cloud Run execution Service Accounts should only be granted `roles/storage.objectUser` on the checkpoint bucket and `roles/secretmanager.secretAccessor` scoped strictly to the individual secret resources, not the entire GCP project.
* **Tenant Isolation**: Direct Chronicle Ingestion requires both `CUSTOMER_ID` and `PROJECT_ID`. The application refuses to fall back to default tenant IDs to prevent cross-tenant data leakage.
* **Checkpoint Tamper Resistance**: Checkpoints validate timestamp syntax (`validate_timestamp_param`) before advancing high-water marks, preventing checkpoint poisoning from malformed datetime data.

