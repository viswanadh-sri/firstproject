import asyncio
from typing import Any, BinaryIO

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
        if api_key is not None:
            raw_key = api_key
        elif configured_key is None:
            raw_key = None
        else:
            get_secret_value = getattr(configured_key, "get_secret_value", None)
            raw_key = (
                get_secret_value()
                if callable(get_secret_value)
                else configured_key
            )
        self.api_key = raw_key.strip() if raw_key else None
        self.base_url = (base_url or settings.virustotal_base_url).rstrip("/")
        self.timeout = timeout or settings.virustotal_timeout_seconds
        self._client = httpx.AsyncClient(timeout=self.timeout)

    async def close(self) -> None:
        await self._client.aclose()

    def _headers(self) -> dict[str, str]:
        if not self.api_key:
            raise VirusTotalError(
                "VirusTotal API key is not configured. Set VIRUSTOTAL_API_KEY.",
                status_code=503,
            )
        return {"x-apikey": self.api_key, "accept": "application/json"}

    @staticmethod
    def _rewind_file_upload(files: Any) -> None:
        if not isinstance(files, dict):
            return
        for value in files.values():
            upload = value[1] if isinstance(value, tuple) and len(value) > 1 else None
            if hasattr(upload, "seek"):
                upload.seek(0)

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

    async def _request(
        self,
        method: str,
        url: str,
        *,
        retry_transient: bool = False,
        **kwargs,
    ) -> httpx.Response:
        attempts = settings.virustotal_retry_attempts if retry_transient else 0
        for attempt in range(attempts + 1):
            try:
                self._rewind_file_upload(kwargs.get("files"))
                response = await self._client.request(
                    method,
                    url,
                    headers=self._headers(),
                    **kwargs,
                )
            except httpx.HTTPError as exc:
                if attempt < attempts:
                    await asyncio.sleep(settings.virustotal_retry_backoff_seconds * (2**attempt))
                    continue
                raise VirusTotalError("VirusTotal is unavailable") from exc

            retryable_status = response.status_code == 429 or response.status_code >= 500
            if response.is_error and retryable_status and attempt < attempts:
                await asyncio.sleep(settings.virustotal_retry_backoff_seconds * (2**attempt))
                continue
            if response.is_error:
                if response.status_code in {401, 403}:
                    raise VirusTotalError(
                        "VirusTotal rejected the API key. Check VIRUSTOTAL_API_KEY.",
                        status_code=502,
                    )
                raise VirusTotalError(
                    f"VirusTotal request failed with status {response.status_code}",
                    status_code=502,
                )
            return response

        raise VirusTotalError("VirusTotal is unavailable")

    async def scan_url(self, url: str) -> dict:
        submission = await self.submit_url(url)
        return await self.get_analysis_report(self._analysis_id(submission))

    async def submit_url(self, url: str) -> dict:
        response = await self._request(
            "POST",
            f"{self.base_url}/urls",
            retry_transient=True,
            data={"url": url},
        )
        return self._json(response)

    async def get_url_report(self, url_id: str) -> dict:
        response = await self._request("GET", f"{self.base_url}/urls/{url_id}")
        return self._json(response)

    async def get_analysis_report_once(self, analysis_id: str) -> dict[str, Any] | None:
        response = await self._request(
            "GET",
            f"{self.base_url}/analyses/{analysis_id}",
        )
        report = self._json(response)
        status = self._analysis_status(report)
        if status == "completed":
            return report
        if status in {"failed", "interrupted"}:
            raise VirusTotalError(
                f"VirusTotal analysis ended with status '{status}'",
                status_code=502,
            )
        return None

    async def get_analysis_report(self, analysis_id: str) -> dict:
        deadline = asyncio.get_running_loop().time() + settings.virustotal_max_poll_seconds
        while True:
            try:
                response = await self._request(
                    "GET",
                    f"{self.base_url}/analyses/{analysis_id}",
                    retry_transient=True,
                )
                report = self._json(response)
            except VirusTotalError as exc:
                if exc.status_code not in {502, 504}:
                    raise
                if asyncio.get_running_loop().time() >= deadline:
                    raise VirusTotalError(
                        "VirusTotal returned no usable analysis data",
                        status_code=502,
                    ) from None
                await asyncio.sleep(settings.virustotal_poll_interval_seconds)
                continue
            status = self._analysis_status(report)

            if status == "completed":
                return report
            if status in {"failed", "interrupted"}:
                raise VirusTotalError(
                    f"VirusTotal analysis ended with status '{status}'",
                    status_code=502,
                )
            if status is None and asyncio.get_running_loop().time() >= deadline:
                raise VirusTotalError(
                    "VirusTotal returned no usable analysis status",
                    status_code=502,
                )
            if asyncio.get_running_loop().time() >= deadline:
                raise VirusTotalError(
                    "VirusTotal analysis did not complete within the allowed time",
                    status_code=504,
                )
            await asyncio.sleep(settings.virustotal_poll_interval_seconds)

    async def _large_file_upload_url(self) -> str:
        response = await self._request(
            "GET",
            f"{self.base_url}/files/upload_url",
            retry_transient=True,
        )
        upload_url = self._json(response).get("data")
        if not isinstance(upload_url, str) or not upload_url.startswith(("https://", "http://")):
            raise VirusTotalError("VirusTotal returned an invalid upload URL")
        return upload_url

    async def scan_file(self, file: BinaryIO, filename: str, content_type: str, size: int) -> dict:
        submission = await self.submit_file(file, filename, content_type, size)
        return await self.get_analysis_report(self._analysis_id(submission))

    async def submit_file(self, file: BinaryIO, filename: str, content_type: str, size: int) -> dict:
        if not filename.strip():
            raise VirusTotalError("A filename is required", status_code=400)
        if size <= 0:
            raise VirusTotalError("The uploaded file is empty", status_code=400)
        if size > MAX_FILE_SIZE:
            raise VirusTotalError("File exceeds the 650 MB VirusTotal limit", status_code=413)
        file.seek(0)

        upload_url = (
            f"{self.base_url}/files"
            if size <= DIRECT_UPLOAD_LIMIT
            else await self._large_file_upload_url()
        )
        response = await self._upload_file(upload_url, file, filename, content_type)
        return self._json(response)

    async def _upload_file(
        self,
        upload_url: str,
        file: BinaryIO,
        filename: str,
        content_type: str,
    ) -> httpx.Response:
        return await self._request(
            "POST",
            upload_url,
            retry_transient=True,
            files={"file": (filename, file, content_type)},
        )


def file_size(file: BinaryIO) -> int:
    current_position = file.tell()
    file.seek(0, 2)
    size = file.tell()
    file.seek(current_position)
    return size
