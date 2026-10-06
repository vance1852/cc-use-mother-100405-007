"""提供不依赖第三方框架的 HTTP/JSON 边界。"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .errors import DomainError, ValidationError
from .participant_service import ParticipantService
from .service import DomainService
from .storage import Database


def route(service: DomainService, method: str, path: str, body: dict[str, Any] | None,
          headers: dict[str, str] | None = None,
          participant_service: ParticipantService | None = None) -> tuple[int, dict[str, Any]]:
    """把一个 HTTP 语义请求分派到领域服务。"""

    headers = headers or {}
    body = body or {}
    parsed = urlparse(path)
    actor_id = headers.get("X-Actor-Id", "")
    participants = participant_service or ParticipantService(service.database, service.clock)
    query = parse_qs(parsed.query)

    def error_payload(exc: DomainError) -> dict[str, Any]:
        payload = {"error": exc.code, "message": str(exc)}
        checks = getattr(exc, "checks", None)
        if checks:
            payload["checks"] = checks
        return payload

    try:
        if method == "GET" and parsed.path == "/health":
            valid, count = service.verify_audit()
            return 200, {"status": "ok", "audit_valid": valid, "audit_events": count}
        if method == "POST" and parsed.path == "/organizations":
            receipt = service.register_organization(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/actors":
            receipt = service.register_actor(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/sites":
            receipt = service.register_site(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/domain-records":
            receipt = service.record_domain_data(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "GET" and parsed.path == "/domain-records":
            site_id = query.get("site_id", [""])[0]
            if not site_id:
                raise ValidationError("site_id 不能为空")
            category = query.get("category", [None])[0]
            return 200, {"items": [item.__dict__ for item in service.list_domain_data(site_id, category)]}
        if method == "GET" and parsed.path == "/audit-events":
            after = int(query.get("after_sequence", ["0"])[0])
            return 200, {"items": service.audit_events(after)}

        status, payload = _participant_routes(participants, method, parsed, body, query, actor_id)
        if status is not None:
            return status, payload
        return 404, {"error": "route_not_found", "message": "接口不存在"}
    except DomainError as exc:
        return exc.status, error_payload(exc)
    except sqlite3.IntegrityError as exc:
        return 409, {"error": "conflict", "message": f"数据约束冲突: {exc}"}
    except (TypeError, ValueError) as exc:
        return 400, {"error": "invalid_request", "message": str(exc)}


def _participant_routes(participants: ParticipantService, method: str, parsed,
                        body: dict[str, Any], query, actor_id: str) -> tuple[int | None, dict[str, Any]]:
    """研究参与者权益与样本使用域的路由。返回 (None, {}) 表示未命中。"""

    path = parsed.path

    if method == "POST":
        if path == "/subject-links":
            return 201, _receipt(participants.link_subject_code(actor_id=actor_id, **body))
        if path == "/participant-merges":
            return 201, _receipt(participants.merge_participants(actor_id=actor_id, **body))
        if path == "/consents":
            return 201, _receipt(participants.record_consent(actor_id=actor_id, **body))
        if path == "/protocols":
            return 201, _receipt(participants.register_protocol(actor_id=actor_id, **body))
        if path == "/protocol-purpose-amendments":
            return 201, _receipt(participants.amend_protocol_purposes(actor_id=actor_id, **body))
        if path == "/irb-approvals":
            return 201, _receipt(participants.record_irb_approval(actor_id=actor_id, **body))
        if path == "/samples":
            return 201, _receipt(participants.register_sample(actor_id=actor_id, **body))
        if path == "/sample-splits":
            return 201, _receipt(participants.split_sample(actor_id=actor_id, **body))
        if path == "/datasets":
            return 201, _receipt(participants.register_dataset(actor_id=actor_id, **body))
        if path == "/dataset-participants":
            return 201, _receipt(participants.add_dataset_participant(actor_id=actor_id, **body))
        if path == "/access-applications":
            return 201, _receipt(participants.submit_application(actor_id=actor_id, **body))
        if path == "/withdrawals":
            return 201, _receipt(participants.withdraw_participant(actor_id=actor_id, **body))
        if path == "/withdrawals/apply-due":
            return 200, participants.apply_due_withdrawals(actor_id=actor_id)
        if path == "/research-outputs":
            return 201, _receipt(participants.record_output(actor_id=actor_id, **body))

        match = re.fullmatch(r"/access-applications/([^/]+)/(decide|release|close)", path)
        if match:
            application_id, action = match.group(1), match.group(2)
            if action == "decide":
                return 200, participants.decide_application(
                    actor_id=actor_id, application_id=application_id,
                    decision=body.get("decision", "approve"),
                    expires_at=body.get("expires_at"))
            if action == "release":
                return 200, participants.release_application(
                    actor_id=actor_id, application_id=application_id)
            return 200, participants.close_application(
                actor_id=actor_id, application_id=application_id)
        match = re.fullmatch(r"/access-applications/([^/]+)/consumptions", path)
        if match:
            return 200, participants.record_consumption(
                actor_id=actor_id, application_id=match.group(1), items=body["items"])
        match = re.fullmatch(r"/obligations/([^/]+)/discharge", path)
        if match:
            return 200, participants.discharge_obligation(
                actor_id=actor_id, obligation_id=match.group(1))

    if method == "GET":
        match = re.fullmatch(r"/access-applications/([^/]+)/explanation", path)
        if match:
            return 200, participants.explain_application(
                actor_id=actor_id, application_id=match.group(1))
        match = re.fullmatch(r"/withdrawals/([^/]+)/impact", path)
        if match:
            return 200, participants.withdrawal_impact(
                actor_id=actor_id, withdrawal_id=match.group(1))
        match = re.fullmatch(r"/samples/([^/]+)", path)
        if match:
            return 200, participants.get_sample(actor_id=actor_id, sample_id=match.group(1))
        if path == "/sample-conservation":
            sample_id = query.get("sample_id", [None])[0]
            return 200, participants.sample_conservation(actor_id=actor_id, sample_id=sample_id)

    return None, {}


def _receipt(receipt) -> dict[str, Any]:
    return {"request_id": receipt.request_id, "resource_type": receipt.resource_type,
            "resource_id": receipt.resource_id, "replayed": receipt.replayed}


class Handler(BaseHTTPRequestHandler):
    """把标准库 HTTP 请求转换为路由调用。"""

    service: DomainService
    participant_service: ParticipantService

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._write(400, {"error": "invalid_json", "message": "请求体必须是 UTF-8 JSON"})
            return
        status, payload = route(self.service, self.command, self.path, body,
                                {"X-Actor-Id": self.headers.get("X-Actor-Id", "")},
                                participant_service=self.participant_service)
        self._write(status, payload)

    def _write(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> int:
    """启动本地 HTTP 服务。"""

    parser = argparse.ArgumentParser(description="启动科技战略协作基础服务")
    parser.add_argument("--database", default="service.sqlite3")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    database = Database(args.database)
    Handler.service = DomainService(database)
    Handler.participant_service = ParticipantService(database)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
