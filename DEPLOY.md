# CertMaster — Deployment & Security Guide

A web tool that detects a certificate's format and converts it to any other
format (PEM, DER, PKCS#12, PFX, P7B, P7C, CER, CRT). Files are processed **in
memory** and never written to disk by the application.

Every detected format can be converted to every other format. Encrypted
PKCS#12 / PFX files can be opened with a supplied password (typed or uploaded
as a small text file), and PKCS#12 / PFX output can optionally be encrypted
with a new password — which the user can also download as a `.txt` file.

> A note on "hack-proof": no internet-facing service is ever truly hack-proof.
> This app applies layered, industry-standard hardening (input validation,
> sanitization, size limits, rate limiting, strict security headers, a locked
> CSP, least-privilege container). Treat security as ongoing: keep dependencies
> patched, run behind TLS, and review the checklist at the end.

---

## 1. Project layout

```
certmaster/
├── main.py             FastAPI app + security middleware
├── cert_utils.py       Format detection & conversion logic
├── security.py         Validation, sanitization, rate limiter, headers
├── requirements.txt    Pinned dependencies
├── Dockerfile          Non-root production image
├── docker-compose.yml  One-command run (read-only, no-new-privileges)
├── .dockerignore
├── DEPLOY.md
└── static/
    ├── index.html      UI (no inline JS/CSS — CSP-clean)
    ├── style.css
    └── app.js
```

---

## 2. Run locally (no Docker)

Requires **Python 3.10+** and the **openssl** CLI (pre-installed on most
Linux/macOS; on Windows use WSL).

```bash
cd certmaster
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>.

---

## 3. Run with Docker (recommended)

```bash
cd certmaster
docker compose up --build -d
```

This builds a slim, **non-root** image, runs it with a **read-only**
filesystem, `no-new-privileges`, and all Linux capabilities dropped. The app
listens on port 8000. Check health:

```bash
curl http://127.0.0.1:8000/healthz      # {"status":"ok"}
```

Stop it:

```bash
docker compose down
```

---

## 4. Put it behind HTTPS (production)

Never expose the app directly over plain HTTP. Run a reverse proxy that
terminates TLS in front of it, and bind the app to `127.0.0.1` so only the
proxy can reach it.

Minimal nginx server block (replace the domain and certificate paths):

```nginx
server {
    listen 443 ssl http2;
    server_name certs.example.com;

    ssl_certificate     /etc/letsencrypt/live/certs.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/certs.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;

    client_max_body_size 2m;          # reject oversized uploads at the edge
    client_body_timeout 15s;
    client_header_timeout 15s;

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Forwarded-For   $remote_addr;   # single trusted hop
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 30s;
    }
}
```

Obtain a free certificate with certbot:

```bash
sudo certbot --nginx -d certs.example.com
```

---

## 5. Deploy to a managed platform

The app is a standard ASGI service and runs anywhere that supports containers.

**Render / Railway / Fly.io / Google Cloud Run / AWS App Runner** — point the
platform at the repo; it will use the `Dockerfile` and the Gunicorn + Uvicorn
start command defined there. Expose port 8000. These platforms provide TLS
automatically, so you can skip the nginx step.

**Generic VPS (systemd, no Docker):**

```ini
# /etc/systemd/system/certmaster.service
[Unit]
Description=CertMaster
After=network.target

[Service]
User=www-data
WorkingDirectory=/opt/certmaster
ExecStart=/opt/certmaster/.venv/bin/gunicorn main:app \
  --worker-class uvicorn.workers.UvicornWorker \
  --workers 2 --bind 127.0.0.1:8000 \
  --max-requests 1000 --max-requests-jitter 100
Restart=always
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now certmaster
```

---

## 6. Configuration

| Env var           | Default   | Meaning                                            |
|-------------------|-----------|----------------------------------------------------|
| `ALLOWED_ORIGINS` | _(empty)_ | Comma-separated CORS origins. Empty = same-origin only (most secure). Set only if a separate front-end domain calls the API. |

Hard limits live in `security.py`:

| Constant               | Default | Meaning                              |
|------------------------|---------|--------------------------------------|
| `MAX_FILE_SIZE`        | 2 MB    | Largest accepted upload              |
| `MAX_CERTS_IN_CHAIN`   | 16      | Cap on certs parsed from one file    |
| `MAX_PASSWORD_LEN`     | 1024    | Largest accepted password            |
| `RATE_LIMIT_REQUESTS`  | 30      | Requests allowed per window per IP   |
| `RATE_LIMIT_WINDOW`    | 60 s    | Rate-limit window length             |

---

## 7. Security measures built in

- **Input validation.** Upload size is bounded *during* read (a huge upload
  can't exhaust memory). Empty files rejected.
- **Content-based detection.** The file's actual bytes decide its format; the
  filename extension is only a tiebreaker, never trusted on its own.
- **Strict target validation.** `target_format` is an enum — any value outside
  the allowed set is rejected with HTTP 422 before any processing.
- **Filename sanitization.** Output filenames are stripped to a safe
  allowlist (`A–Z a–z 0–9 . _ -`), with directory components and CR/LF
  removed — blocks path traversal and HTTP header injection.
- **No XSS in the UI.** All dynamic values are inserted with `textContent`,
  never `innerHTML`.
- **Strict CSP.** No inline scripts or styles; scripts and styles load only
  from same-origin (fonts from Google Fonts). Plus `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Permissions-Policy`, and cross-origin isolation headers.
- **Rate limiting.** Per-IP sliding window (default 30 req/min) returns 429.
- **Safe subprocess use.** The openssl CLI is invoked with an argument list
  (never a shell string) and a timeout — no shell injection possible.
- **Password handling.** Passwords are bounded in length, used only in memory
  to open or encrypt PKCS#12/PFX, and never logged or stored. A wrong or
  missing password returns HTTP 401, never a server error or stack trace.
- **No data retention.** Nothing is written to disk; converted bytes are
  streamed back and discarded. The container runs read-only.
- **Reduced attack surface.** Auto-generated API docs (`/docs`, `/openapi.json`)
  are disabled. Container runs as a non-root user with dropped capabilities.

---

## 8. Important operational notes

- **Rate limiter is per-process.** With multiple Gunicorn workers or instances,
  each has its own counter. For a strict global limit, enforce it at the
  proxy/CDN (nginx `limit_req`, Cloudflare) or use a Redis-backed limiter.
- **Always run behind TLS** in production. Enable HSTS only after confirming
  HTTPS works everywhere.
- **Keep dependencies patched.** `cryptography` and `pyOpenSSL` are security-
  sensitive. Periodically run `pip list --outdated` and rebuild.

---

## 9. Pre-launch checklist

- [ ] Served over HTTPS with a valid certificate
- [ ] App port not exposed publicly (only the proxy can reach it)
- [ ] `client_max_body_size` set at the proxy (2 MB)
- [ ] Rate limiting enforced at the edge if you run multiple workers
- [ ] Dependencies up to date; image rebuilt
- [ ] `/docs` and `/openapi.json` return 404 (confirm)
