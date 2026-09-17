from urllib.parse import urlsplit

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse
from pydantic import AnyHttpUrl, BaseModel, field_validator
from pymongo.errors import PyMongoError

from app.db.mongodb import get_database
from app.limiter import limiter
from app.routers.auth import current_user
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


async def _save_submission(user: dict, kind: str, target: str, submission: dict) -> None:
    analysis_id = service._analysis_id(submission)
    try:
        await get_database().scan_records.insert_one(
            {
                "user_id": user["_id"],
                "analysis_id": analysis_id,
                "kind": kind,
                "target": target,
                "created_at": datetime.now(UTC),
            }
        )
    except PyMongoError as exc:
        raise HTTPException(status_code=500, detail="The scan was submitted but could not be saved.") from exc


async def _attach_report(user: dict, analysis_id: str, report: dict) -> None:
    try:
        await get_database().scan_records.update_one(
            {"user_id": user["_id"], "analysis_id": analysis_id},
            {"$set": {"report": report, "completed_at": datetime.now(UTC)}},
        )
    except PyMongoError as exc:
        raise HTTPException(status_code=500, detail="The scan completed but could not be updated.") from exc


@limiter.limit("10/minute")
@router.post("/urls", status_code=status.HTTP_200_OK)
async def scan_url(request: Request, payload: URLScanRequest, user=Depends(current_user)):
    target = str(payload.url)
    submission = await _call(lambda: service.submit_url(target))
    await _save_submission(user, "URL", target, submission)
    return submission


@router.get("/history")
async def scan_history(user=Depends(current_user)):
    records = (
        get_database()
        .scan_records
        .find({"user_id": user["_id"]})
        .sort("created_at", -1)
        .limit(50)
    )
    return [
        {
            "id": str(record["_id"]),
            "kind": record["kind"],
            "target": record["target"],
            "report": record["report"],
            "created_at": record["created_at"],
        }
        async for record in records if record.get("report")
    ]


@router.get("/urls/{url_id}/report")
async def url_report(url_id: str, user=Depends(current_user)):
    if not url_id or len(url_id) > 512 or "/" in url_id:
        raise HTTPException(status_code=400, detail="Invalid VirusTotal URL ID")
    return await _call(lambda: service.get_url_report(url_id))


@router.get("/analyses/{analysis_id}/report")
async def analysis_report(analysis_id: str, user=Depends(current_user)):
    if not analysis_id or len(analysis_id) > 512 or "/" in analysis_id:
        raise HTTPException(status_code=400, detail="Invalid VirusTotal analysis ID")
    report = await _call(lambda: service.get_analysis_report_once(analysis_id))
    if report is None:
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={"status": "pending", "analysis_id": analysis_id},
        )
    await _attach_report(user, analysis_id, report)
    return report


@router.post("/files", status_code=status.HTTP_200_OK)
async def scan_file(file: UploadFile = File(...), user=Depends(current_user)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="A filename is required")
    size = file_size(file.file)
    try:
        submission = await _call(
            lambda: service.submit_file(
                file.file,
                file.filename,
                file.content_type or "application/octet-stream",
                size,
            )
        )
        await _save_submission(user, "File", file.filename, submission)
        return submission
    finally:
        await file.close()
