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
- The forgot-password endpoint intentionally returns the same response whether an email exists to reduce account enumeration. Connect the generated token to an email provider before production use; do not expose reset tokens in the API response.
- VirusTotal integration is available at `/virustotal/urls`, `/virustotal/urls/{url_id}/report`, and `/virustotal/files`. Set `VIRUSTOTAL_API_KEY` in `.env`; it is never returned by the API.
- Files up to 32 MB use VirusTotal's direct upload endpoint. Larger files use the temporary upload URL returned by VirusTotal, up to the service's 650 MB limit.
