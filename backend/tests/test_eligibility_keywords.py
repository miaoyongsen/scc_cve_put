import os
os.environ.setdefault("API_TOKEN", "test-only")

from app.eligibility import evaluate


def config(primary):
    return {
        "severities": {"严重", "高危", "中危", "低危", "未知"},
        "hours": 0,
        "primary": primary,
    }


def test_high_severity_primary_keyword_pushes():
    assert evaluate({"title": "Apache remote code execution", "severity": "高危"}, config(["apache"])) == (
        "primary", "apache", None
    )


def test_high_severity_non_primary_keyword_is_filtered():
    assert evaluate({"title": "Jenkins remote code execution", "severity": "高危"}, config(["apache"])) == (
        None, None, "keyword"
    )


def test_unknown_severity_still_requires_primary_for_review():
    assert evaluate({"title": "Apache issue", "severity": "未知"}, config(["apache"])) == (
        "secondary", "等级未知", None
    )
    assert evaluate({"title": "Jenkins issue", "severity": "未知"}, config(["apache"])) == (
        None, None, "keyword"
    )


def test_low_medium_severity_remain_filtered():
    for severity in ("中危", "低危"):
        assert evaluate({"title": "Apache issue", "severity": severity}, config(["apache"])) == (
            None, None, "severity"
        )


def test_empty_primary_retains_original_known_severity_fallback():
    assert evaluate({"title": "Any issue", "severity": "严重"}, config([])) == (
        "primary", None, None
    )
    assert evaluate({"title": "Any issue", "severity": "未知"}, config([])) == (
        None, None, "keyword"
    )
