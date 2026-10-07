# Build stage / Production image
FROM python:3.12-slim AS runtime

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install security updates and ca-certificates
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy application source code into package directory
COPY . /app/salesforce_secops

# Create non-root system user for least privilege execution
RUN groupadd -r secops && useradd -r -g secops -u 1001 secops && \
    chown -R secops:secops /app

USER 1001:1001

# Default entrypoint for Cloud Run Jobs: run incremental polling
ENTRYPOINT ["python3", "-m", "salesforce_secops.sync"]
CMD ["poll"]
