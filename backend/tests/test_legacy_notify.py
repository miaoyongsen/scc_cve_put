from app.legacy_notify import format_wecom
def test_original_message_format():
    assert format_wecom({"title":"X","cve":"CVE-2026-1","severity":"高危","from":"avd","disclosure":"2026-10-21"}) == (
        "## WatchVuln 漏洞情报\n"
        "> **标题**：X\n"
        "> **CVE**：CVE-2026-1\n"
        "> **等级**：高危\n"
        "> **来源**：avd\n"
        "> **披露日期**：2026-10-21\n"
        "> 请前往 IP Sentinel 漏洞监控查看详情"
    )
