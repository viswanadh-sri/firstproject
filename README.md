# FastAPI MongoDB Atlas Authentication

## Setup

1. Create and activate a virtual environment.
2. Install dependencies: `pip install -r requirements.txt`.
3. Copy `.env.example` to `.env` and set the MongoDB Atlas URI and a random JWT secret of at least 32 characters.
4. Start the app: `uvicorn Main:app --reload`.
5. Open `http://localhost:8000/` for the login page.

## Security notes

- User documents store bcrypt password hashes, never plaintext passwords.
- JWT access tokens are placed in `HttpOnly` cookies. A separate readable CSRF cookie must be echoed in `X-CSRF-Token` for state-changing cookie-authenticated requests.
- Set `COOKIE_SECURE=true` behind HTTPS in production.
- Pydantic models reject unsupported display-name characters, control characters, and oversized input. Jinja2 autoescaping is enabled for the HTML template.
- The forgot-password endpoint sends a hashed, six-digit reset OTP through SMTP and intentionally returns the same response for unknown email addresses. Reset with `POST /auth/reset-password` using `email`, `token`, and `new_password`; the OTP is not returned by the API, expires according to `PASSWORD_RESET_EXPIRE_MINUTES`, and is deleted after successful verification.
- Standalone OTP verification is also available at `POST /otp/request` and `POST /otp/verify`. Configure the `SMTP_*` variables in `.env`; standalone OTPs expire after five minutes and are deleted after successful verification.
- VirusTotal integration is available at `/virustotal/urls`, `/virustotal/urls/{url_id}/report`, `/virustotal/analyses/{analysis_id}/report`, and `/virustotal/files`. The scan response contains an analysis ID, which must be fetched through the `/analyses/{analysis_id}/report` endpoint; `/urls/{url_id}/report` is for a VirusTotal URL identifier. Set `VIRUSTOTAL_API_KEY` in `.env`; it is never returned by the API.
- File scans use a multipart field named `file`. Files up to 32 MB use `POST /files`; larger files use VirusTotal's upload URL, up to the 650 MB limit. The service rewinds the stream before retries, rejects empty files, and reports missing or rejected API-key configuration without exposing the key.
- VirusTotal URL and file submissions now wait for their analysis to reach `completed` before returning. The HTTP client timeout is 60 seconds and polling runs for up to 180 seconds by default; tune `VIRUSTOTAL_TIMEOUT_SECONDS` and `VIRUSTOTAL_MAX_POLL_SECONDS` in `.env` as needed. Network errors and HTTP 429/5xx responses are retried with exponential backoff using `VIRUSTOTAL_RETRY_ATTEMPTS` and `VIRUSTOTAL_RETRY_BACKOFF_SECONDS`. A timeout returns HTTP 504, while failed or interrupted analyses return HTTP 502.
- Files up to 32 MB use VirusTotal's direct upload endpoint. Larger files use the temporary upload URL returned by VirusTotal, up to the service's 650 MB limit.

## React authentication frontend

The responsive React/Tailwind authentication module is in `frontend/`.

```bash
cd frontend
npm install
npm run dev
```

The Vite development server proxies `/auth` requests to the FastAPI server at `http://localhost:8000`. The forgot-password screen follows the current backend contract: it requests reset instructions and then submits the reset token with the new password.
