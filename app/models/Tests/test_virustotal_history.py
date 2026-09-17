from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio
from bson import ObjectId

from app.main import app
from app.routers import auth, virustotal
from app.services.virustotal import VirusTotalService

pytestmark = pytest.mark.asyncio


async def test_virustotal_uses_x_apikey_header():
    service = VirusTotalService(api_key="test-api-key")

    assert service._headers() == {
        "x-apikey": "test-api-key",
        "accept": "application/json",
    }


@pytest_asyncio.fixture
async def client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as test_client:
        yield test_client


async def test_scan_saves_authenticated_user_id(client, monkeypatch):
    user_id = ObjectId()
    scan_records = SimpleNamespace(insert_one=AsyncMock())
    database = SimpleNamespace(scan_records=scan_records)
    submission = {"data": {"id": "analysis-123", "attributes": {"status": "queued"}}}
    monkeypatch.setattr(virustotal, "get_database", lambda: database)
    monkeypatch.setattr(virustotal.service, "submit_url", AsyncMock(return_value=submission))
    app.dependency_overrides[auth.current_user] = lambda: {"_id": user_id}

    try:
        response = await client.post("/virustotal/urls", json={"url": "https://example.com"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    inserted = scan_records.insert_one.await_args.args[0]
    assert inserted["user_id"] == user_id
    assert inserted["analysis_id"] == "analysis-123"
    assert inserted["kind"] == "URL"
    assert inserted["target"] == "https://example.com/"


async def test_history_filters_by_authenticated_user_id(client, monkeypatch):
    user_id = ObjectId()
    records = [
        {
            "_id": ObjectId(),
            "user_id": user_id,
            "kind": "File",
            "target": "invoice.pdf",
            "report": {"data": {"attributes": {}}},
            "created_at": "2026-09-17T00:00:00Z",
        }
    ]

    class Cursor:
        def sort(self, *args):
            self.sort_args = args
            return self

        def limit(self, value):
            self.limit_value = value
            return self

        def __aiter__(self):
            return self._records()

        async def _records(self):
            for record in records:
                yield record

    cursor = Cursor()
    scan_records = SimpleNamespace(find=lambda query: setattr(cursor, "find_query", query) or cursor)
    monkeypatch.setattr(virustotal, "get_database", lambda: SimpleNamespace(scan_records=scan_records))
    app.dependency_overrides[auth.current_user] = lambda: {"_id": user_id}

    try:
        response = await client.get("/virustotal/history")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()[0]["target"] == "invoice.pdf"
    assert cursor.find_query == {"user_id": user_id}
    assert cursor.sort_args == ("created_at", -1)
    assert cursor.limit_value == 50
