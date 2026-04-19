"""Tests for input validation constraints on request models."""

import pytest
from pydantic import ValidationError

from src.models import BreachReconRequest


class TestBreachReconRequestValidation:
    def test_accepts_10_emails(self):
        req = BreachReconRequest(
            targets=["example.com"],
            emails=[f"user{i}@example.com" for i in range(10)],
        )
        assert len(req.emails) == 10

    def test_rejects_over_100_emails(self):
        with pytest.raises(ValidationError):
            BreachReconRequest(
                targets=["example.com"],
                emails=[f"user{i}@example.com" for i in range(101)],
            )

    def test_accepts_100_emails(self):
        req = BreachReconRequest(
            targets=["example.com"],
            emails=[f"user{i}@example.com" for i in range(100)],
        )
        assert len(req.emails) == 100
