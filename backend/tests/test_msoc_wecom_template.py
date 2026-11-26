"""MSOC customizable WeCom Markdown template regression coverage."""
import json
from fastapi import HTTPException
from app import msoc_monitor as msoc


def test_msoc_template_fields_and_multiline_disposal():
    source = {
        "ticket_identifier": "300-205029",
        "priority": "Medium",
        "cause": "Escalated",
        "escalation": "AWS_Guardduty_Guardduty Findings",
        "disposal": "告警详情：\n源地址IP：172.24.254.245\n\n建议：\n确认授权",
        "ticket_url": "",
    }
    item = {"source_id": 12, "source_month": "202611",
            "received_at": "2026-11-26T09:00:00+08:00",
            "content": json.dumps(source, ensure_ascii=False)}
    body = msoc._format_delivery(item, msoc.DEFAULT_MESSAGE_TEMPLATE)
    assert "300-205029" in body
    assert "Escalated" in body
    assert "源地址IP：172.24.254.245\n\n建议：" in body
    assert "{disposal}" not in body
    assert "[查看工单]" not in body


def test_msoc_template_keeps_unknown_json_accessible():
    item = {"source_id": 1, "source_month": "202611",
            "received_at": "2026-11-26", "content": '{"recent":true}'}
    assert '"recent":true' in msoc._format_delivery(item)


def test_msoc_template_rejects_unsupported_fields():
    try:
        msoc._validate_template("## {invalid_field}")
    except HTTPException as error:
        assert error.status_code == 422
    else:
        raise AssertionError("unsupported placeholder accepted")


def test_msoc_template_uses_saved_layout():
    item = {"source_id": 1, "source_month": "202611",
            "received_at": "2026-11-26",
            "content": '{"ticket_identifier":"ABC","disposal":"first\\nsecond"}'}
    body = msoc._format_delivery(item, "Ticket: {ticket_identifier}\\n{disposal}")
    assert body == "Ticket: ABC\nfirst\nsecond"
