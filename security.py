"""
Security helpers: input validation, filename sanitization, size limits,
and a lightweight in-memory per-IP rate limiter.
"""
import os
import re
import time
import threading
from collections import defaultdict, deque
from enum import Enum

# ---------------------------------------------------------------------------
# Hard limits
# ---------------------------------------------------------------------------

MAX_FILE_SIZE = 2 * 1024 * 1024        # 2 MB — certs are tiny; reject anything bigger
MAX_CERTS_IN_CHAIN = 16                 # guard against decompression / chain bombs
MAX_FILENAME_LEN = 64

# Rate limit: N requests per WINDOW seconds, per client IP
RATE_LIMIT_REQUESTS = 30
RATE_LIMIT_WINDOW = 60                  # seconds


# ---------------------------------------------------------------------------
# Allowed target formats (Enum gives automatic 422 on bad input via FastAPI)
# ---------------------------------------------------------------------------

class TargetFormat(str, Enum):
    PEM = "PEM"
    DER = "DER"
    PKCS12 = "PKCS12"
    PFX = "PFX"
    P7B = "P7B"
    P7C = "P7C"
    CER = "CER"
    CRT = "CRT"


# Output formats that support encryption with a password
PASSWORD_PROTECTABLE = {"PKCS12", "PFX"}

# Reasonable bound on password length (defends against pathological input)
MAX_PASSWORD_LEN = 1024


# ---------------------------------------------------------------------------
# Filename sanitization — prevents path traversal & header injection
# ---------------------------------------------------------------------------

_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]")

def safe_stem(filename: str | None) -> str:
    """
    Reduce an arbitrary uploaded filename to a safe stem usable in a
    Content-Disposition header. Strips directories, control chars,
    quotes, CR/LF, and limits length.
    """
    base = os.path.basename(filename or "")          # drop any path component
    base = base.replace("\x00", "")                  # drop nulls
    stem = base.rsplit(".", 1)[0] if "." in base else base
    stem = _SAFE_CHARS.sub("_", stem)                # allowlist only
    stem = stem.strip("._")                          # no leading/trailing junk
    if not stem:
        stem = "certificate"
    return stem[:MAX_FILENAME_LEN]


# ---------------------------------------------------------------------------
# Upload validation
# ---------------------------------------------------------------------------

def validate_upload_size(data: bytes) -> str | None:
    """Return an error string if invalid, else None."""
    if len(data) == 0:
        return "Uploaded file is empty."
    if len(data) > MAX_FILE_SIZE:
        return f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)} MB."
    return None


# ---------------------------------------------------------------------------
# In-memory rate limiter (per IP, sliding window)
#
# NOTE: This is per-process. If you run multiple workers/instances, use a
# shared store (e.g. Redis) instead. See DEPLOY.md.
# ---------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, max_requests: int, window: int):
        self.max_requests = max_requests
        self.window = window
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, client_id: str) -> bool:
        now = time.time()
        with self._lock:
            q = self._hits[client_id]
            # drop timestamps outside the window
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.max_requests:
                return False
            q.append(now)
            # opportunistic cleanup to bound memory
            if len(self._hits) > 10_000:
                self._cleanup(now)
            return True

    def _cleanup(self, now: float):
        stale = [k for k, q in self._hits.items()
                 if not q or q[-1] <= now - self.window]
        for k in stale:
            del self._hits[k]


rate_limiter = RateLimiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW)


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

# Strict CSP. No inline JS/CSS allowed (we serve external files). Fonts come
# from Google Fonts; everything else is same-origin only.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}
