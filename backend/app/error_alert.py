"""Send detailed operational errors to a dedicated WeCom bot."""
import logging
from datetime import datetime
from .notifications import send_wecom_text

log=logging.getLogger(__name__)

def send_error_alert(source, detail, force=False):
    from .push_config import current
    config=current()
    webhook=config.get("error_wecom_webhook") or ""
    if not webhook or (not force and not config.get("error_wecom_enabled")):
        return False
    # Operational alerts never depend on user-managed templates or AI services.
    # WeCom text messages have simpler rendering and fewer formatting pitfalls.
    try:
        source_text=str(source).replace("\\r"," ").replace("\\n"," ")[:160]
        detail_text=str(detail).replace("\\r","")[:2500]
        content=("【SCC CVE 异常告警】\\n"
                 "任务："+source_text+"\\n"
                 "时间："+datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")+"\\n"
                 "详情：\\n"+detail_text)
    except Exception:
        log.exception("Failed to format error alert; using minimal fallback")
        content="【SCC CVE 异常告警】\\n采集或推送发生异常，请查看服务器日志。"
    return send_wecom_text(content,url=webhook)

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
        errors=["采集任务状态异常，但未记录具体错误，请检查运行详情和服务器日志。"]
    try:
        delivered=send_error_alert(mode+"（"+status+"）","\n".join("• "+str(x) for x in errors[:20]))
        if not delivered:
            log.warning("Operational alert skipped: error bot disabled or webhook missing; mode=%s status=%s",mode,status)
    except Exception:
        log.exception("Failed to send operational error alert")
