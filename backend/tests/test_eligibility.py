from app.eligibility import keyword_matches, allow_unknown_review_upgrade


def test_starred_go_matches_complete_word_but_not_go_extension():
    assert keyword_matches("Go runtime vulnerability", "*go*")
    assert not keyword_matches("Campcodes loan system banner.go", "*go*")
    assert not keyword_matches("gopher library vulnerability", "*go*")


def test_starred_phrase_matches_words_in_order():
    assert keyword_matches("Linux   kernel privilege escalation", "*linux kernel*")
    assert not keyword_matches("Linux-kernel privilege escalation", "*linux kernel*")
    assert not keyword_matches("MyLinux kernel issue", "*linux kernel*")


def test_php_keyword_does_not_match_php_file_extension():
    assert keyword_matches("PHP authentication bypass", "php")
    assert not keyword_matches("Campcodes banner.php file", "php")


def test_pending_unknown_cve_is_promoted_even_if_new_title_misses_keywords():
    item = {"cve": "CVE-2026-12345", "severity": "高危"}
    tier, matched, rejected = allow_unknown_review_upgrade(
        item, None, None, "keyword", True
    )
    assert (tier, matched, rejected) == ("primary", "等级未知升级", None)


def test_pending_unknown_cve_promotes_secondary_match_to_primary():
    item = {"cve": "CVE-2026-12345", "severity": "严重"}
    tier, matched, rejected = allow_unknown_review_upgrade(
        item, "secondary", "review-word", None, True
    )
    assert (tier, matched, rejected) == ("primary", "等级未知升级", None)


def test_upgrade_does_not_bypass_date_or_configured_severity_rejection():
    item = {"cve": "CVE-2026-12345", "severity": "高危"}
    assert allow_unknown_review_upgrade(item, None, None, "date", True) == (
        None, None, "date"
    )
    assert allow_unknown_review_upgrade(item, None, None, "severity", True) == (
        None, None, "severity"
    )


def test_no_pending_unknown_review_keeps_normal_keyword_decision():
    item = {"cve": "CVE-2026-12345", "severity": "高危"}
    assert allow_unknown_review_upgrade(item, None, None, "keyword", False) == (
        None, None, "keyword"
    )
