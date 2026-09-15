from typing import BinaryIO

import httpx

from app.core.config import settings

DIRECT_UPLOAD_LIMIT = 32 * 1024 * 1024
MAX_FILE_SIZE = 650 * 1024 * 1024


class VirusTotalError(RuntimeError):
    """Raised when VirusTotal cannot complete a requested operation."""

    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


class VirusTotalService:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
    ):
        configured_key = settings.virustotal_api_key
        self.api_key = api_key or (configured_key.get_secret_value() if configured_key else None)
        self.base_url = (base_url or settings.virustotal_base_url).rstrip("/")
        self.timeout = timeout or settings.virustotal_timeout_seconds

    def _headers(self) -> dict[str, str]:
        if not self.api_key:
            raise VirusTotalError("VirusTotal API key is not configured", status_code=503)
        return {"x-apikey": self.api_key, "accept": "application/json"}

    async def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.request(method, url, headers=self._headers(), **kwargs)
        except httpx.HTTPError as exc:
            raise VirusTotalError("VirusTotal is unavailable") from exc
        if response.is_error:
            raise VirusTotalError(
                f"VirusTotal request failed with status {response.status_code}",
                status_code=502,
            )
        return response

    async def scan_url(self, url: str) -> dict:
        response = await self._request("POST", f"{self.base_url}/urls", data={"url": url})
        return response.json()

    async def get_url_report(self, url_id: str) -> dict:
        response = await self._request("GET", f"{self.base_url}/urls/{url_id}")
        return response.json()

    async def _large_file_upload_url(self) -> str:
        response = await self._request("GET", f"{self.base_url}/files/upload_url")
        upload_url = response.json().get("data")
        if not isinstance(upload_url, str) or not upload_url.startswith(("https://", "http://")):
            raise VirusTotalError("VirusTotal returned an invalid upload URL")
        return upload_url

    async def scan_file(self, file: BinaryIO, filename: str, content_type: str, size: int) -> dict:
        if size > MAX_FILE_SIZE:
            raise VirusTotalError("File exceeds the 650 MB VirusTotal limit", status_code=413)

        upload_url = (
            f"{self.base_url}/files"
            if size <= DIRECT_UPLOAD_LIMIT
            else await self._large_file_upload_url()
        )
        response = await self._upload_file(upload_url, file, filename, content_type)
        return response.json()

    async def _upload_file(
        self,
        upload_url: str,
        file: BinaryIO,
        filename: str,
        content_type: str,
    ) -> httpx.Response:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    upload_url,
                    headers=self._headers(),
                    files={"file": (filename, file, content_type)},
                )
        except httpx.HTTPError as exc:
            raise VirusTotalError("VirusTotal is unavailable") from exc
        if response.is_error:
            raise VirusTotalError(
                f"VirusTotal file upload failed with status {response.status_code}",
                status_code=502,
            )
        return response


def file_size(file: BinaryIO) -> int:
    current_position = file.tell()
    file.seek(0, 2)
    size = file.tell()
    file.seek(current_position)
    return size
