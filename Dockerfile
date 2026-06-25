# ---- Build a small, non-root production image ----
FROM python:3.12-slim AS base

# openssl CLI is required for PKCS#7 (.p7b) conversion
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

# Create an unprivileged user to run the app
RUN useradd --create-home --uid 10001 appuser

WORKDIR /app

# Install Python deps first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Drop privileges
USER appuser

EXPOSE 8000

# Gunicorn manages Uvicorn workers. Tune workers to your CPU count.
# Note: the in-memory rate limiter is per-worker; see DEPLOY.md for multi-worker notes.
CMD ["gunicorn", "main:app", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--workers", "2", \
     "--bind", "0.0.0.0:8000", \
     "--timeout", "30", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100"]
