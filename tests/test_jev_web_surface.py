"""Opt-in Jev page classification and data-minimisation checks."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from src.app import app
from src.crawler import _web_surface_fields
from src.jev_web_surface import assess_page, build_state
from src.models import JevPageAssessment, LinkInfo, PageResult


def test_form_evidence_drops_values_and_action_query():
    soup = BeautifulSoup(
        '<h1>Account</h1><form action="/login?token=private" method="post">'
        '<input type="email" value="person@example.com">'
        '<input type="password" value="secret"></form>',
        "html.parser",
    )
    headings, forms = _web_surface_fields(soup, "https://example.com/")
    assert headings == ["Account"]
    assert forms == [{
        "method": "POST", "action_host": "example.com", "action_path": "/login",
        "input_types": ["email", "password"],
    }]
    assert "secret" not in str(forms)
    assert "person@example.com" not in str(forms)


@pytest.mark.asyncio
async def test_jev_receives_bounded_evidence_and_parses_typed_answers():
    page = PageResult(
        url="https://example.com/login?session=private",
        status_code=200,
        title="Account",
        headings=["Sign in"],
        forms=[{"method": "POST", "action_host": "example.com", "input_types": ["password"]}],
        content_snippet="person@example.com secret",
        links=[LinkInfo(url="https://payments.example.org/pay?token=secret", anchor_text="Pay", link_type="external")],
    )
    response = httpx.Response(200, json={
        "model": "jev-1.13.0",
        "answers": {
            "page_role": {"type": "choice", "choice": "login", "confidence": 0.9},
            "credential_surface": {"type": "noul", "noul": 0.98},
            "external_workflow": {"type": "noul", "noul": 0.4},
        },
    }, request=httpx.Request("POST", "https://api.typesafe.ai/v1/systemone"))
    client = AsyncMock()
    client.post.return_value = response
    client.__aenter__.return_value = client
    with patch("src.jev_web_surface.httpx.AsyncClient", return_value=client):
        result = await assess_page(page, api_key="test-key")
    payload = client.post.call_args.kwargs["json"]
    assert payload["state"]["url"] == "https://example.com/login"
    assert payload["state"]["links"] == [{"label": "Pay", "destination_host": "payments.example.org"}]
    assert "person@example.com" not in str(payload)
    assert "secret" not in str(payload)
    assert result.page_role == "login"
    assert result.credential_surface_probability == 0.98


@pytest.mark.asyncio
async def test_unusable_page_is_not_sent_to_jev():
    page = PageResult(url="https://example.com/", status_code=202, title="Challenge")
    with patch("src.jev_web_surface.httpx.AsyncClient") as client:
        result = await assess_page(page, api_key="test-key")
    assert result.status == "skipped"
    client.assert_not_called()


def test_endpoint_requires_server_key(monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    response = TestClient(app).post("/recon/jev-web-surface", json={"targets": ["https://example.com"]})
    assert response.status_code == 503


def test_endpoint_caps_paid_assessments(monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", "test-key")
    response = TestClient(app).post(
        "/recon/jev-web-surface",
        json={"targets": ["https://example.com"], "max_jev_pages": 6},
    )
    assert response.status_code == 422


def test_endpoint_returns_advisory_page_result(monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", "test-key")
    page = PageResult(url="https://example.com/", status_code=200, title="Home")
    assessment = JevPageAssessment(
        page_url=page.url, model="jev-1.13.0", page_role="public_content",
        page_role_confidence=0.8, credential_surface_probability=0.01,
        external_workflow_probability=0.2,
    )
    with patch("src.routers.content.crawl_domain", new_callable=AsyncMock, return_value=[page]), \
         patch("src.routers.content.assess_page", new_callable=AsyncMock, return_value=assessment):
        response = TestClient(app).post(
            "/recon/jev-web-surface", json={"targets": ["https://example.com"], "max_depth": 0},
        )
    assert response.status_code == 200
    result = response.json()[0]
    assert result["pages_assessed"] == 1
    assert result["assessments"][0]["page_role"] == "public_content"
    assert "risk_assessment" not in result
