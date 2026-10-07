#!/usr/bin/env bash
# Deploy Salesforce to Google SecOps Integration to Cloud Run Jobs
set -euo pipefail

# Configuration - Fail fast if mandatory tenant identifiers are not provided
if [[ -z "${PROJECT_ID:-}" ]]; then
    echo "ERROR: PROJECT_ID environment variable is required."
    exit 1
fi
if [[ -z "${CUSTOMER_ID:-}" ]]; then
    echo "ERROR: CUSTOMER_ID environment variable is required (Google SecOps customer UUID)."
    exit 1
fi

REGION="${REGION:-us-central1}"
SECOPS_REGION="${SECOPS_REGION:-us}"
JOB_NAME="salesforce-secops-sync"
REPO_NAME="secops-integrations"
IMAGE_TAG="v1.0.0"
SERVICE_ACCOUNT="salesforce-secops-runner@${PROJECT_ID}.iam.gserviceaccount.com"
CHECKPOINT_BUCKET="gs://${PROJECT_ID}-secops-state"

echo "==========================================================="
echo " Deploying Salesforce SecOps Integration to Cloud Run Jobs"
echo " Project:       ${PROJECT_ID}"
echo " Region:        ${REGION}"
echo " Customer ID:   ${CUSTOMER_ID}"
echo "==========================================================="

# 1. Enable Required GCP APIs
echo "Enabling GCP APIs..."
gcloud services enable \
    run.googleapis.com \
    cloudscheduler.googleapis.com \
    artifactregistry.googleapis.com \
    secretmanager.googleapis.com \
    storage.googleapis.com \
    chronicle.googleapis.com \
    --project="${PROJECT_ID}"

# 2. Create Artifact Registry Repository (if not existing)
echo "Checking Artifact Registry..."
if ! gcloud artifacts repositories describe "${REPO_NAME}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "Creating Artifact Registry repository: ${REPO_NAME}..."
    gcloud artifacts repositories create "${REPO_NAME}" \
        --repository-format=docker \
        --location="${REGION}" \
        --project="${PROJECT_ID}" \
        --description="Google SecOps Custom Integrations"
fi

IMAGE_URI="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/${JOB_NAME}:${IMAGE_TAG}"

# 3. Build & Push Container Image using Cloud Build
echo "Building and pushing container image: ${IMAGE_URI}..."
gcloud builds submit --tag "${IMAGE_URI}" --project="${PROJECT_ID}"

# 4. Create State Bucket for High-Water Mark Checkpoints
echo "Checking State Bucket..."
if ! gsutil ls -b "${CHECKPOINT_BUCKET}" >/dev/null 2>&1; then
    echo "Creating GCS bucket: ${CHECKPOINT_BUCKET}..."
    gsutil mb -p "${PROJECT_ID}" -c STANDARD -l "${REGION}" "${CHECKPOINT_BUCKET}"
fi

# 5. Create Service Account (if not existing)
if ! gcloud iam service-accounts describe "${SERVICE_ACCOUNT}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "Creating dedicated Service Account: ${SERVICE_ACCOUNT}..."
    gcloud iam service-accounts create "salesforce-secops-runner" \
        --display-name="Salesforce to SecOps Runner" \
        --project="${PROJECT_ID}"
fi

# 6. Grant Permissions (Least Privilege)
echo "Granting IAM permissions to ${SERVICE_ACCOUNT}..."
# Storage permissions for checkpointing (scoped to bucket objectUser)
gcloud storage buckets add-iam-policy-binding "${CHECKPOINT_BUCKET}" \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/storage.objectUser" >/dev/null 2>&1 || \
    gsutil iam ch "serviceAccount:${SERVICE_ACCOUNT}:objectAdmin" "${CHECKPOINT_BUCKET}"

# Secret Manager permissions: Scoped strictly to the 3 required secrets (NOT project-wide)
echo "Granting per-secret Secret Accessor permissions..."
for secret in salesforce-client-id salesforce-username salesforce-private-key; do
    gcloud secrets add-iam-policy-binding "${secret}" \
        --member="serviceAccount:${SERVICE_ACCOUNT}" \
        --role="roles/secretmanager.secretAccessor" \
        --project="${PROJECT_ID}" >/dev/null
done

# 7. Create or Update Cloud Run Job
echo "Deploying Cloud Run Job: ${JOB_NAME}..."
gcloud run jobs deploy "${JOB_NAME}" \
    --image="${IMAGE_URI}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --service-account="${SERVICE_ACCOUNT}" \
    --set-env-vars="CUSTOMER_ID=${CUSTOMER_ID},PROJECT_ID=${PROJECT_ID},REGION=${SECOPS_REGION},CHECKPOINT_BACKEND=gcs,CHECKPOINT_PATH=${CHECKPOINT_BUCKET}/checkpoints/salesforce_state.json,SALESFORCE_AUTH_TYPE=jwt" \
    --set-secrets="SALESFORCE_CLIENT_ID=salesforce-client-id:latest,SALESFORCE_USERNAME=salesforce-username:latest,SALESFORCE_PRIVATE_KEY=salesforce-private-key:latest" \
    --max-retries=1 \
    --task-timeout=600s \
    --cpu=1 \
    --memory=512Mi

# 8. Create Cloud Scheduler Job (Runs every 10 minutes)
SCHEDULER_JOB="salesforce-secops-scheduler"
echo "Setting up Cloud Scheduler: ${SCHEDULER_JOB} (every 10 minutes)..."
if gcloud scheduler jobs describe "${SCHEDULER_JOB}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud scheduler jobs update http "${SCHEDULER_JOB}" \
        --location="${REGION}" \
        --project="${PROJECT_ID}" \
        --schedule="*/10 * * * *" \
        --uri="https://${REGION}-run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/jobs/${JOB_NAME}:run" \
        --http-method=POST \
        --oauth-service-account-email="${SERVICE_ACCOUNT}"
else
    gcloud scheduler jobs create http "${SCHEDULER_JOB}" \
        --location="${REGION}" \
        --project="${PROJECT_ID}" \
        --schedule="*/10 * * * *" \
        --uri="https://${REGION}-run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/jobs/${JOB_NAME}:run" \
        --http-method=POST \
        --oauth-service-account-email="${SERVICE_ACCOUNT}"
fi

echo "==========================================================="
echo " Deployment Complete!"
echo " To execute an ad-hoc run:"
echo "   gcloud run jobs execute ${JOB_NAME} --region=${REGION} --project=${PROJECT_ID}"
echo "==========================================================="
