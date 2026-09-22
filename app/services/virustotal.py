import time
from typing import Any, BinaryIO

import httpx

from app.core.config import settings

DIRECT_UPLOAD_LIMIT = 32 * 1024 * 1024
MAX_FILE_SIZE = 650 * 1024 * 1024


class VirusTotalError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


class VirusTotalService:
    def __init__(self, api_key: str | None = None, base_url: str | None = None, timeout: float | None = None):
        configured = settings.virustotal_api_key
        raw_key = api_key if api_key is not None else (configured.get_secret_value() if configured else None)
        self.api_key = raw_key.strip() if raw_key else None
        self.base_url = (base_url or settings.virustotal_base_url).rstrip("/")
        self.timeout = timeout or settings.virustotal_timeout_seconds
        self._client = httpx.Client(timeout=self.timeout)

    def close(self) -> None:
        self._client.close()

    def _headers(self) -> dict[str, str]:
        if not self.api_key:
            raise VirusTotalError("VirusTotal API key is not configured. Set VIRUSTOTAL_API_KEY.", 503)
        return {"x-apikey": self.api_key, "accept": "application/json"}

    @staticmethod
    def _analysis_status(payload: dict[str, Any]) -> str | None:
        data = payload.get("data")
        attributes = data.get("attributes") if isinstance(data, dict) else None
        status = attributes.get("status") if isinstance(attributes, dict) else None
        return status.lower() if isinstance(status, str) else None

    @staticmethod
    def _analysis_id(payload: dict[str, Any]) -> str:
        data = payload.get("data")
        analysis_id = data.get("id") if isinstance(data, dict) else None
        if not isinstance(analysis_id, str) or not analysis_id:
            raise VirusTotalError("VirusTotal returned an invalid analysis identifier")
        return analysis_id

    @staticmethod
    def _json(response: httpx.Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise VirusTotalError("VirusTotal returned invalid JSON") from exc
        if not isinstance(payload, dict) or not payload:
            raise VirusTotalError("VirusTotal returned an empty response")
        return payload

    def _request(self, method: str, url: str, *, retry_transient: bool = False, **kwargs) -> httpx.Response:
        attempts = settings.virustotal_retry_attempts if retry_transient else 0
        for attempt in range(attempts + 1):
            try:
                response = self._client.request(method, url, headers=self._headers(), **kwargs)
            except httpx.HTTPError as exc:
                if attempt < attempts:
                    time.sleep(settings.virustotal_retry_backoff_seconds * (2 ** attempt))
                    continue
                raise VirusTotalError("VirusTotal is unavailable") from exc
            if response.is_error and (response.status_code == 429 or response.status_code >= 500) and attempt < attempts:
                time.sleep(settings.virustotal_retry_backoff_seconds * (2 ** attempt))
                continue
            if response.is_error:
                if response.status_code in {401, 403}:
                    raise VirusTotalError("VirusTotal rejected the API key. Check VIRUSTOTAL_API_KEY.")
                raise VirusTotalError(f"VirusTotal request failed with status {response.status_code}")
            return response
        raise VirusTotalError("VirusTotal is unavailable")

    def submit_url(self, url: str) -> dict:
        return self._json(self._request("POST", f"{self.base_url}/urls", retry_transient=True, data={"url": url}))

    def get_url_report(self, url_id: str) -> dict:
        return self._json(self._request("GET", f"{self.base_url}/urls/{url_id}"))

    def get_analysis_report_once(self, analysis_id: str) -> dict[str, Any] | None:
        report = self._json(self._request("GET", f"{self.base_url}/analyses/{analysis_id}"))
        status = self._analysis_status(report)
        if status == "completed":
            return report
        if status in {"failed", "interrupted"}:
            raise VirusTotalError(f"VirusTotal analysis ended with status '{status}'")
        return None

    def _large_file_upload_url(self) -> str:
        value = self._json(self._request("GET", f"{self.base_url}/files/upload_url", retry_transient=True)).get("data")
        if not isinstance(value, str) or not value.startswith(("https://", "http://")):
            raise VirusTotalError("VirusTotal returned an invalid upload URL")
        return value

    def submit_file(self, file: BinaryIO, filename: str, content_type: str, size: int) -> dict:
        if not filename.strip():
            raise VirusTotalError("A filename is required", 400)
        if size <= 0:
            raise VirusTotalError("The uploaded file is empty", 400)
        if size > MAX_FILE_SIZE:
            raise VirusTotalError("File exceeds the 650 MB VirusTotal limit", 413)
        file.seek(0)
        upload_url = f"{self.base_url}/files" if size <= DIRECT_UPLOAD_LIMIT else self._large_file_upload_url()
        return self._json(self._request("POST", upload_url, retry_transient=True,
                                        files={"file": (filename, file, content_type)}))


def file_size(file: BinaryIO) -> int:
    position = file.tell()
    file.seek(0, 2)
    size = file.tell()
    file.seek(position)
    return size
