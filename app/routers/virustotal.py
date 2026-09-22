from urllib.parse import urlsplit
from datetime import UTC, datetime

from flask import Blueprint, jsonify, request
from pymongo.errors import PyMongoError
from werkzeug.exceptions import BadRequest, InternalServerError

from app.db.mongodb import get_database
from app.routers.auth import current_user
from app.services.virustotal import VirusTotalError, VirusTotalService, file_size

virustotal_bp = Blueprint("virustotal", __name__, url_prefix="/virustotal")
service = VirusTotalService()


def _call(operation):
    try:
        return operation()
    except VirusTotalError as exc:
        error = BadRequest(str(exc)) if exc.status_code == 400 else InternalServerError(str(exc))
        error.code = exc.status_code
        raise error from exc


def _save_submission(user: dict, kind: str, target: str, submission: dict) -> None:
    try:
        get_database().scan_records.insert_one({"user_id": user["_id"], "analysis_id": service._analysis_id(submission),
                                                "kind": kind, "target": target, "created_at": datetime.now(UTC)})
    except PyMongoError as exc:
        raise InternalServerError("The scan was submitted but could not be saved.") from exc


def _attach_report(user: dict, analysis_id: str, report: dict) -> None:
    try:
        get_database().scan_records.update_one({"user_id": user["_id"], "analysis_id": analysis_id},
                                               {"$set": {"report": report, "completed_at": datetime.now(UTC)}})
    except PyMongoError as exc:
        raise InternalServerError("The scan completed but could not be updated.") from exc


@virustotal_bp.post("/urls")
def scan_url():
    user = current_user()
    payload = request.get_json(silent=True)
    target = payload.get("url") if isinstance(payload, dict) else None
    parsed = urlsplit(target) if isinstance(target, str) else None
    if not parsed or parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise BadRequest("Only valid HTTP(S) URLs without embedded credentials are supported")
    target = target.strip()
    if not target:
        raise BadRequest("URL is required")
    submission = _call(lambda: service.submit_url(target))
    _save_submission(user, "URL", target, submission)
    return jsonify(submission)


@virustotal_bp.get("/history")
def scan_history():
    user = current_user()
    records = get_database().scan_records.find({"user_id": user["_id"]}).sort("created_at", -1).limit(50)
    return jsonify([{"id": str(record["_id"]), "kind": record["kind"], "target": record["target"],
                    "report": record["report"], "created_at": record["created_at"]} for record in records if record.get("report")])


@virustotal_bp.get("/urls/<url_id>/report")
def url_report(url_id: str):
    current_user()
    if not url_id or len(url_id) > 512 or "/" in url_id:
        raise BadRequest("Invalid VirusTotal URL ID")
    return jsonify(_call(lambda: service.get_url_report(url_id)))


@virustotal_bp.get("/analyses/<analysis_id>/report")
def analysis_report(analysis_id: str):
    user = current_user()
    if not analysis_id or len(analysis_id) > 512 or "/" in analysis_id:
        raise BadRequest("Invalid VirusTotal analysis ID")
    report = _call(lambda: service.get_analysis_report_once(analysis_id))
    if report is None:
        return jsonify(status="pending", analysis_id=analysis_id), 202
    _attach_report(user, analysis_id, report)
    return jsonify(report)


@virustotal_bp.post("/files")
def scan_file():
    user = current_user()
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        raise BadRequest("A filename is required")
    size = file_size(uploaded.stream)
    submission = _call(lambda: service.submit_file(uploaded.stream, uploaded.filename,
                                                   uploaded.content_type or "application/octet-stream", size))
    _save_submission(user, "File", uploaded.filename, submission)
    return jsonify(submission)
