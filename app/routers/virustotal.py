from urllib.parse import urlsplit

from fastapi import APIRouter, File, HTTPException, Request, UploadFile, status
from pydantic import AnyHttpUrl, BaseModel, field_validator

from app.limiter import limiter
from app.services.virustotal import VirusTotalError, VirusTotalService, file_size

router = APIRouter(prefix="/virustotal", tags=["VirusTotal"])
service = VirusTotalService()


class URLScanRequest(BaseModel):
    url: AnyHttpUrl

    @field_validator("url")
    @classmethod
    def require_public_http_url(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        parsed = urlsplit(str(value))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Only valid HTTP(S) URLs are supported")
        if parsed.username or parsed.password:
            raise ValueError("URLs with embedded credentials are not supported")
        return value


async def _call(operation):
    try:
        return await operation()
    except VirusTotalError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@limiter.limit("10/minute")
@router.post("/urls", status_code=status.HTTP_200_OK)
async def scan_url(request: Request, payload: URLScanRequest):
    return await _call(lambda: service.scan_url(str(payload.url)))


@router.get("/urls/{url_id}/report")
async def url_report(url_id: str):
    if not url_id or len(url_id) > 512 or "/" in url_id:
        raise HTTPException(status_code=400, detail="Invalid VirusTotal URL ID")
    return await _call(lambda: service.get_url_report(url_id))


@router.get("/analyses/{analysis_id}/report")
async def analysis_report(analysis_id: str):
    if not analysis_id or len(analysis_id) > 512 or "/" in analysis_id:
        raise HTTPException(status_code=400, detail="Invalid VirusTotal analysis ID")
    return await _call(lambda: service.get_analysis_report(analysis_id))


@router.post("/files", status_code=status.HTTP_200_OK)
async def scan_file(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="A filename is required")
    size = file_size(file.file)
    try:
        return await _call(
            lambda: service.scan_file(
                file.file,
                file.filename,
                file.content_type or "application/octet-stream",
                size,
            )
        )
    finally:
        await file.close()
