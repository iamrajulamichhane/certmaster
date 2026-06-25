"""
CertMaster — hardened FastAPI backend.

Security measures:
- Strict per-request size cap (read is bounded, not just checked after).
- Content-based format detection (extension is never trusted alone).
- Target format constrained to an Enum (invalid values -> 422 automatically).
- Output filename sanitized (no path traversal / header injection).
- Per-IP in-memory rate limiting.
- Security headers (CSP, nosniff, frame-deny, no-referrer, etc.) on every response.
- CORS restricted to configured origins (default: same-origin only).
- Generic error messages; internal exceptions never leaked to clients.

Password handling:
- Encrypted PKCS#12 / PFX uploads: client supplies the password (typed or via
  an uploaded password file). The server reports needs_password instead of
  failing, so the UI can prompt.
- PKCS#12 / PFX output: client may supply an output password to encrypt the file.
"""
import os

from fastapi import FastAPI, File, UploadFile, HTTPException, Form, Request
from fastapi.responses import Response, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from cert_utils import (
    detect_format, convert_certificate, is_encrypted_pkcs12,
    FORMAT_EXTENSIONS, FORMAT_DESCRIPTIONS,
)
from security import (
    TargetFormat, safe_stem, validate_upload_size,
    rate_limiter, SECURITY_HEADERS, MAX_FILE_SIZE,
    MAX_PASSWORD_LEN, PASSWORD_PROTECTABLE,
)

BASE_DIR = os.path.dirname(__file__)
STATIC_DIR = os.path.join(BASE_DIR, "static")

ALLOWED_ORIGINS = [o for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o]

app = FastAPI(title="CertMaster", docs_url=None, redoc_url=None, openapi_url=None)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers[k] = v
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/api/"):
            client_ip = request.client.host if request.client else "unknown"
            fwd = request.headers.get("x-forwarded-for")
            if fwd:
                client_ip = fwd.split(",")[0].strip()
            if not rate_limiter.allow(client_ip):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests. Please slow down."},
                )
        return await call_next(request)


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)

if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
        max_age=600,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _read_bounded(file: UploadFile) -> bytes:
    data = await file.read(MAX_FILE_SIZE + 1)
    err = validate_upload_size(data)
    if err:
        raise HTTPException(status_code=413 if len(data) > MAX_FILE_SIZE else 400,
                            detail=err)
    return data


def _clean_password(pw: str | None) -> bytes | None:
    if pw is None:
        return None
    pw = pw.strip("\r\n")
    if not pw:
        return None
    if len(pw) > MAX_PASSWORD_LEN:
        raise HTTPException(status_code=400, detail="Password too long.")
    return pw.encode("utf-8")


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@app.post("/api/detect")
async def detect(file: UploadFile = File(...)):
    data = await _read_bounded(file)
    fmt, description, error = detect_format(data, file.filename or "")
    if error:
        raise HTTPException(status_code=422, detail=error)

    needs_password = fmt in PASSWORD_PROTECTABLE and is_encrypted_pkcs12(data)

    # Every detected format can be converted to every other format.
    targets = [f for f in FORMAT_EXTENSIONS if f != fmt]
    return {
        "detected_format": fmt,
        "description": description,
        "filename": safe_stem(file.filename) + "." + FORMAT_EXTENSIONS.get(fmt, "crt"),
        "size": len(data),
        "needs_password": needs_password,
        "possible_targets": [
            {
                "format": t,
                "label": FORMAT_DESCRIPTIONS[t],
                "ext": FORMAT_EXTENSIONS[t],
                "supports_password": t in PASSWORD_PROTECTABLE,
            }
            for t in targets
        ],
    }


@app.post("/api/convert")
async def convert(
    file: UploadFile = File(...),
    target_format: TargetFormat = Form(...),
    password: str | None = Form(None),          # to open an encrypted source
    output_password: str | None = Form(None),   # to encrypt PKCS#12/PFX output
):
    data = await _read_bounded(file)

    src_fmt, _, error = detect_format(data, file.filename or "")
    if error:
        raise HTTPException(status_code=422, detail=error)

    tgt = target_format.value
    src_pw = _clean_password(password)
    out_pw = _clean_password(output_password)
    if out_pw and tgt not in PASSWORD_PROTECTABLE:
        out_pw = None  # ignore output password for formats that can't use it

    # If source is an encrypted PKCS#12 and no password was supplied, ask for one.
    if src_fmt in PASSWORD_PROTECTABLE and not src_pw and is_encrypted_pkcs12(data):
        return JSONResponse(
            status_code=401,
            content={"detail": "Password required to open this PKCS#12/PFX.",
                     "needs_password": True},
        )

    converted, mime, err = convert_certificate(
        data, src_fmt, tgt, password=src_pw, output_password=out_pw
    )
    if err:
        # Wrong/missing password surfaces here for encrypted sources
        status = 401 if "password" in err.lower() else 422
        raise HTTPException(status_code=status, detail=err)

    filename = f"{safe_stem(file.filename)}.{FORMAT_EXTENSIONS[tgt]}"
    return Response(
        content=converted,
        media_type=mime,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
