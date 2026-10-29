"""Send detailed operational errors to a dedicated WeCom bot."""
import logging
from datetime import datetime
from .notifications import send_wecom_markdown

log=logging.getLogger(__name__)

def send_error_alert(source, detail, force=False):
    from .push_config import current
    config=current()
    webhook=config.get("error_wecom_webhook") or ""
    if not webhook or (not force and not config.get("error_wecom_enabled")):
        return False
    content=("## SCC CVE 采集异常告警\n"
             "> **来源/任务**："+str(source).replace("\n"," ")[:160]+"\n"
             "> **时间**："+datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")+"\n"
             "> **异常详情**：\n"+str(detail).replace("\r","")[:2500])
    return send_wecom_markdown(content,url=webhook)

def alert_run_errors(mode, status, summary):
    if status not in ("失败","部分失败"):
        return
    errors=list(summary.get("errors") or [])
    for entry in summary.get("details") or []:
        if entry.get("status") in ("error","partial") or entry.get("ok") is False:
            name=entry.get("name") or entry.get("id") or "未知来源"
            errors.append("来源："+str(name)+"；状态："+str(entry.get("status") or "失败")+
                          "；HTTP："+str(entry.get("http_status") or "未知")+
                          "；错误："+str(entry.get("error") or "; ".join(entry.get("notification_errors") or []) or "采集或推送异常"))
    if not errors and summary.get("error"):
        errors=[str(summary["error"])]
    if not errors:
        return
    try:
        send_error_alert(mode+"（"+status+"）","\n".join("• "+str(x) for x in errors[:20]))
    except Exception:
        log.exception("Failed to send operational error alert")
