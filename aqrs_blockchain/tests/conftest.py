from __future__ import annotations

import uuid

from flask import Flask
from flask.testing import FlaskClient


class SecurityAwareTestClient(FlaskClient):
    def open(self, *args, **kwargs):
        csrf = kwargs.pop("csrf", True)
        idempotency = kwargs.pop("idempotency", True)
        method = str(kwargs.get("method", "GET")).upper()
        if csrf and method not in {"GET", "HEAD", "OPTIONS", "TRACE"}:
            headers = dict(kwargs.get("headers") or {})
            if not any(name.lower() == "x-csrf-token" for name in headers):
                self.get("/login")
                with self.session_transaction() as current_session:
                    token = current_session.get("csrf_token")
                if token:
                    headers["X-CSRF-Token"] = token
            if (
                method == "POST"
                and idempotency
                and args
                and str(args[0]).split("?", 1)[0] == "/api/transactions"
                and not any(name.lower() == "idempotency-key" for name in headers)
            ):
                headers["Idempotency-Key"] = str(uuid.uuid4())
            kwargs["headers"] = headers
        return super().open(*args, **kwargs)


Flask.test_client_class = SecurityAwareTestClient
