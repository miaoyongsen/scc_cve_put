"""Regression tests for WeCom UTF-8 byte limits and no-data-loss splitting."""
from app import notifications


def test_split_long_chinese_markdown_without_losing_characters():
    content = "## 安全漏洞通知\n" + ("严重漏洞中文测试🚨" * 700) + "\n[原始数据](https://example.com)\n"
    parts = notifications.split_wecom_markdown(content, 3720)
    assert len(parts) > 1
    assert "".join(parts) == content
    assert all(len(x.encode("utf-8")) <= 3720 for x in parts)


def test_markdown_sender_sends_all_segments(monkeypatch):
    sent = []
    monkeypatch.setattr(notifications, "_send_wecom", lambda payload, url=None: sent.append(payload) or True)
    content = "## 漏洞情报\n" + ("这是一份非常长的漏洞通告说明。" * 800)
    assert notifications.send_wecom_markdown(content, url="https://example.invalid") is True
    assert len(sent) >= 2
    raw = []
    for number, payload in enumerate(sent, 1):
        assert payload["msgtype"] == "markdown"
        text = payload["markdown"]["content"]
        assert len(text.encode("utf-8")) <= 3800
        if len(sent) > 1:
            heading = f"> 消息分段 {number}/{len(sent)}\n"
            assert text.startswith(heading)
            text = text[len(heading):]
        raw.append(text)
    assert "".join(raw) == content


def test_sender_does_not_report_success_if_any_segment_fails(monkeypatch):
    attempts = []
    def fake_send(payload, url=None):
        attempts.append(payload)
        return len(attempts) != 2
    monkeypatch.setattr(notifications, "_send_wecom", fake_send)
    assert notifications.send_wecom_markdown("测试" * 3000) is False
    assert len(attempts) == 2


def test_text_alert_uses_2048_byte_limit(monkeypatch):
    sent = []
    monkeypatch.setattr(notifications, "_send_wecom", lambda payload, url=None: sent.append(payload) or True)
    content = "异常告警：" + ("数据库连接故障" * 500)
    assert notifications.send_wecom_text(content)
    assert len(sent) > 1
    assert "".join(p["text"]["content"] for p in sent) == content
    assert all(len(p["text"]["content"].encode("utf-8")) <= 2048 for p in sent)


def test_long_single_message_does_not_leave_tiny_orphan_tail():
    content="安全漏洞详细信息：" + ("中文漏洞描述" * 205)
    parts=notifications.split_wecom_markdown(content, 900)
    assert len(parts)>1
    assert "".join(parts)==content
    assert all(len(part.encode("utf-8"))<=900 for part in parts)
    assert len(parts[-1].encode("utf-8"))>=225


def test_digest_groups_keep_complete_vulnerability_records():
    from app.notification_digest import build_digest_chunks, _bytes
    header="## SCC CVE 漏洞情报汇总\n> 共 4 条\n"
    entries=[({"key":str(i),"title":"Title "+str(i)}, "details") for i in range(4)]
    lines=[
        "\n> **1. 漏洞一**\n" + "描述" * 350,
        "\n> **2. 漏洞二**\n" + "描述" * 280,
        "\n> **3. 漏洞三**\n" + "描述" * 330,
        "\n> **4. 漏洞四**\n" + "描述" * 270,
    ]
    chunks=build_digest_chunks(header, entries, lines)
    assert len(chunks)>1
    assert [item["key"] for _,group in chunks for item in group]==["0","1","2","3"]
    for text,group in chunks:
        assert _bytes(text)+120<=3500
        assert len(group)>=1
    # Every entry is present completely, exactly once, and in original order.
    assert "".join(text[len(header):] for text,_ in chunks)=="".join(lines)


def test_digest_single_oversized_entry_is_isolated():
    from app.notification_digest import build_digest_chunks
    header="## 汇总\n"
    entries=[({"key":"a"}, ""),({"key":"b"}, ""),({"key":"c"}, "")]
    lines=["常规" * 80, "极长" * 1400, "正常" * 90]
    chunks=build_digest_chunks(header, entries, lines)
    assert [[item["key"] for item in rows] for _,rows in chunks]==[["a"],["b"],["c"]]
