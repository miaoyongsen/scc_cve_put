"""Regression checks for MSOC WeCom formatting without sending messages."""
import json
import os

os.environ.setdefault("API_TOKEN", "test-only")
from app import msoc_monitor


def _row(disposal):
    return {
        "source_id": 123,
        "source_month": "202611",
        "received_at": "2026-11-26T09:57:52+08:00",
        "content": json.dumps({
            "ticket_identifier": "300-205029",
            "priority": "Medium",
            "cause": "Escalated",
            "escalation": "AWS_Guardduty Findings",
            "disposal": disposal
        }, ensure_ascii=False),
    }


def test_default_template_separates_sections_and_fixes_escaped_newlines():
    disposal = (
        r"告警详情：\\n告警标题：EC2 instance uses unusual port"
        r"\\n源地址IP：172.24.254.245"
        r"\\n\\n告警分析：\\nGuardDuty 检测到异常通信。"
        r"\\n\\n建议：\\n请确认是否为授权操作。"
    )
    result = msoc_monitor._format_delivery(_row(disposal))
    assert result.count("MSOC 安全告警通知") == 1
    assert "**告警详情**\n告警标题：EC2 instance uses unusual port" in result
    assert "源地址IP：172.24.254.245" in result
    assert "**告警分析**\nGuardDuty 检测到异常通信。" in result
    assert "**处置建议**\n请确认是否为授权操作。" in result
    assert r"\\n" not in result


def test_missing_sections_not_fabricated_and_raw_data_still_available():
    row = _row("Unstructured vendor alert")
    result = msoc_monitor._format_delivery(row)
    assert "**告警详情**\nUnstructured vendor alert" in result
    assert "**告警分析**\n未提供" in result
    assert "**处置建议**\n未提供" in result
    legacy = msoc_monitor._format_delivery(row, "{disposal}")
    assert legacy == "Unstructured vendor alert"
