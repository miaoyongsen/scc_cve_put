"""WAF result routing contract; no real S3 or WeCom requests."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app.waf_monitor import validate_webhook, send_wecom, TERMINAL_SUCCESS, TERMINAL_FAILURE


class FakeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {"errcode": 0}


class WafMonitorTests(unittest.TestCase):
    def test_outcome_classes(self):
        self.assertIn("done", TERMINAL_SUCCESS)
        self.assertIn("failed", TERMINAL_FAILURE)
        self.assertNotIn("pending", TERMINAL_SUCCESS + TERMINAL_FAILURE)
        self.assertNotIn("processing", TERMINAL_SUCCESS + TERMINAL_FAILURE)

    def test_webhook_valid_host(self):
        good="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=example"
        self.assertEqual(validate_webhook(good),good)
        for bad in (
            "http://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=a",
            "https://qyapi.weixin.qq.com.evil.test/cgi-bin/webhook/send?key=a",
            "https://example.com/cgi-bin/webhook/send?key=a",
        ):
            with self.assertRaises(HTTPException):
                validate_webhook(bad)

    @patch("app.waf_monitor.httpx.post")
    def test_messages_go_to_supplied_webhook(self, post):
        post.return_value=FakeResponse()
        row=SimpleNamespace(client_request_id="scc_is_202611240001",
                            service_request_id="123",block_ip="192.0.2.25/32",
                            status="Done",created_at=None)
        url="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=example"
        send_wecom(url,row,"success")
        args, kwargs=post.call_args
        self.assertEqual(args[0],url)
        self.assertIn("封禁成功",kwargs["json"]["text"]["content"])
        self.assertIn("192.0.2.25/32",kwargs["json"]["text"]["content"])
        row.status="Failed"
        send_wecom(url,row,"failure")
        self.assertIn("封禁失败",post.call_args.kwargs["json"]["text"]["content"])


if __name__ == "__main__":
    unittest.main()
