# CertMaster

A fast, privacy-friendly web tool for detecting and converting SSL/TLS
certificate formats. Upload a certificate in any common format, CertMaster
identifies it automatically, and you can convert it to any other format and
download the result. **Nothing is stored** — every file is processed in memory
and discarded after the response.

Built with **FastAPI** and a dependency-free vanilla-JS frontend.

---

## Features

- **Auto-detection** — the certificate's format is identified from its actual
  bytes, not just the file extension.
- **Convert between any formats** — PEM, DER, PKCS#12, PFX, P7B, P7C, CER, CRT.
  Every format can be converted to every other.
- **Password support** — open password-protected PKCS#12 / PFX files (type the
  password or upload it as a `.txt`), and optionally encrypt PKCS#12 / PFX
  output with a new password that you can download as a file.
- **No storage** — files never touch disk; conversions happen entirely in
  memory and are streamed straight back to the browser.
- **Hardened by default** — strict input validation, filename sanitization,
  size limits, per-IP rate limiting, a locked-down Content-Security-Policy,
  and a non-root, read-only container.
- **Drag-and-drop UI** that resets cleanly on every new upload.

## Supported formats

| Format | Extensions | Notes |
|--------|------------|-------|
| PEM | `.pem` | Base64 ASCII |
| DER | `.der` | Binary |
| PKCS#12 | `.p12` | Key/cert bundle; password-protected files supported |
| PFX | `.pfx` | PKCS#12 variant |
| PKCS#7 | `.p7b`, `.p7c` | Certificate chain |
| CER | `.cer` | DER or PEM |
| CRT | `.crt` | PEM or DER |

## Tech stack

- **Backend:** Python, FastAPI, `cryptography`, `pyOpenSSL`, OpenSSL CLI
- **Frontend:** HTML + CSS + vanilla JavaScript (no build step, CSP-clean)
- **Deployment:** Docker / Gunicorn + Uvicorn

---

## Quick start

### Run locally

Requires Python 3.10+ and the `openssl` CLI (pre-installed on most
Linux/macOS; on Windows use WSL).

```bash
git clone https://github.com/<your-username>/certmaster.git
cd certmaster
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>.

### Run with Docker

```bash
docker compose up --build -d
curl http://127.0.0.1:8000/healthz   # {"status":"ok"}
```

See [`DEPLOY.md`](DEPLOY.md) for production deployment, HTTPS setup, and the
full security overview.

---

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/detect` | Upload a certificate; returns its detected format and the list of conversion targets. |
| `POST` | `/api/convert` | Upload a certificate plus a `target_format`; returns the converted file. |
| `GET` | `/healthz` | Health check. |

**`/api/convert` form fields:** `file`, `target_format` (one of the supported
formats), optional `password` (to open an encrypted source), optional
`output_password` (to encrypt PKCS#12 / PFX output).

Example:

```bash
curl -X POST http://127.0.0.1:8000/api/convert \
  -F "file=@certificate.pem" \
  -F "target_format=DER" \
  -o certificate.der
```

---

## Security

CertMaster applies layered, industry-standard hardening: content-based format
detection, strict enum-validated inputs, output-filename sanitization (blocks
path traversal and header injection), bounded upload sizes, per-IP rate
limiting, a strict CSP with no inline scripts or styles, safe subprocess usage,
and a non-root read-only container. Passwords are used only in memory and never
logged or stored.

No internet-facing service is ever truly "hack-proof" — keep dependencies
patched, run behind TLS, and review the checklist in [`DEPLOY.md`](DEPLOY.md).

To report a security issue, please open a private advisory rather than a public
issue.

---

## Configuration

| Env var | Default | Meaning |
|---------|---------|---------|
| `ALLOWED_ORIGINS` | _(empty)_ | Comma-separated CORS origins. Empty = same-origin only. |

Hard limits (file size, chain length, rate limit, password length) live in
`security.py`.

---

## License

Released under the MIT License. See [`LICENSE`](LICENSE) for details.
