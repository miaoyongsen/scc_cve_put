import os
os.environ.setdefault("API_TOKEN", "test-only")

from app.eligibility import evaluate


def config(keywords, severities=None):
    if severities is None:
        severities = {"严重", "高危", "未知"}
    return {
        "severities": set(severities),
        "hours": 0,
        "keywords": keywords,
    }


def test_high_severity_matching_keyword_pushes():
    assert evaluate({"title": "Apache remote code execution", "severity": "高危", "cve": "CVE-2026-12345"}, config(["apache"])) == (
        "direct", "apache", None
    )


def test_high_severity_without_keyword_is_filtered():
    assert evaluate({"title": "Jenkins remote code execution", "severity": "高危", "cve": "CVE-2026-12346"}, config(["apache"])) == (
        None, None, "keyword"
    )


def test_unknown_severity_still_requires_keyword_for_review():
    assert evaluate({"title": "Apache issue", "severity": "未知", "cve": "CVE-2026-12347"}, config(["apache"])) == (
        "review", "等级未知", None
    )
    assert evaluate({"title": "Jenkins issue", "severity": "未知", "cve": "CVE-2026-12348"}, config(["apache"])) == (
        None, None, "keyword"
    )


def test_medium_low_rejected_when_unchecked_in_frontend():
    for severity in ("中危", "低危"):
        assert evaluate({"title": "Apache issue", "severity": severity, "cve": "CVE-2026-12349"}, config(["apache"])) == (
            None, None, "severity"
        )


def test_medium_low_allowed_when_checked_in_frontend():
    for severity in ("中危", "低危"):
        assert evaluate(
            {"title": "Apache issue", "severity": severity, "cve": "CVE-2026-12349"},
            config(["apache"], {"严重", "高危", "中危", "低危", "未知"}),
        ) == ("direct", "apache", None)


def test_severity_filter_applies_even_when_no_keyword_configured():
    assert evaluate({"title": "Any issue", "severity": "中危", "cve": "CVE-2026-12350"}, config([])) == (
        None, None, "severity"
    )
    assert evaluate(
        {"title": "Any issue", "severity": "中危", "cve": "CVE-2026-12350"},
        config([], {"中危"}),
    ) == ("direct", None, None)


def test_empty_keywords_retains_original_known_severity_fallback():
    assert evaluate({"title": "Any issue", "severity": "严重", "cve": "CVE-2026-12351"}, config([])) == (
        "direct", None, None
    )
    assert evaluate({"title": "Any issue", "severity": "未知", "cve": "CVE-2026-12352"}, config([])) == (
        None, None, "keyword"
    )


def test_no_cve_matching_keyword_goes_to_review():
    for severity in ("严重", "高危", "未知"):
        assert evaluate(
            {"title": "Apache security bulletin", "severity": severity, "cve": ""},
            config(["apache"]),
        ) == ("review", "缺少CVE", None)


def test_no_cve_without_matching_keyword_is_filtered():
    assert evaluate(
        {"title": "Unrelated security bulletin", "severity": "高危", "cve": ""},
        config(["apache"]),
    ) == (None, None, "keyword")


def test_invalid_cve_with_keyword_goes_to_review():
    assert evaluate(
        {"title": "Apache flaw", "severity": "高危", "cve": "not-a-cve"},
        config(["apache"]),
    ) == ("review", "缺少CVE", None)


def test_no_cve_does_not_go_direct_when_keyword_list_empty():
    assert evaluate(
        {"title": "Security notice", "severity": "严重", "cve": ""},
        config([]),
    ) == (None, None, "keyword")


def test_valid_cve_is_accepted():
    assert evaluate(
        {"title": "Apache flaw", "severity": "高危", "cve": "CVE-2026-12345"},
        config(["apache"]),
    ) == ("direct", "apache", None)
