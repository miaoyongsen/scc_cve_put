"""Check that operational alerts use the editable markdown template."""
from app import error_alert


def test_configured_error_template_preserves_lines(monkeypatch):
    sent=[]
    monkeypatch.setattr("app.push_config.current",lambda:{
        "error_wecom_webhook":"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test",
        "error_wecom_enabled":True,
        "error_message_template":"## 异常告警\n任务：{task}\n时间：{time}\n错误详情：\n{details}",
    })
    monkeypatch.setattr(error_alert,"send_wecom_markdown",
        lambda content,url=None: sent.append((content,url)) or True)
    assert error_alert.send_error_alert(
        "统一采集（部分失败）",
        "奇安信cve采集: 408:爬虫执行超过35秒\n来源：奇安信cve采集"
    )
    assert len(sent)==1
    content,url=sent[0]
    assert content.startswith("## 异常告警\n任务：统一采集（部分失败）")
    assert "\n> • 奇安信cve采集:" in content
    assert "\n> • 来源：" in content
    assert "\\n" not in content
    assert url.startswith("https://qyapi.weixin.qq.com/")


def test_legacy_escaped_line_breaks_are_normalized(monkeypatch):
    messages=[]
    monkeypatch.setattr("app.push_config.current",lambda:{
        "error_wecom_webhook":"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test",
        "error_wecom_enabled":True,
        "error_message_template":r"任务：{task}\n{details}",
    })
    monkeypatch.setattr(error_alert,"send_wecom_markdown",
        lambda content,url=None: messages.append(content) or True)
    assert error_alert.send_error_alert("任务",r"错误一\n错误二")
    assert "任务：任务\n> • 错误一\n> • 错误二" in messages[0]
