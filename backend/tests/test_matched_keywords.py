"""Matched keyword display should use exactly the existing eligibility semantics."""
from app.eligibility import matching_keywords, evaluate


def test_multiple_keywords_match_title():
    item={"title":"Critical Apache Tomcat and Spring issue", "cve":"CVE-2026-12345", "severity":"高危"}
    words=["Apache","Tomcat","Spring","Redis"]
    assert matching_keywords(item,words)==["Apache","Tomcat","Spring"]
    tier,first,rejected=evaluate(item,{
        "severities":{"高危"},"hours":0,
        "keywords":[x.casefold() for x in words]
    })
    assert (tier,first,rejected)==("direct","apache",None)


def test_keyword_match_deduplicates_case_variants():
    assert matching_keywords({"title":"Apache server"},["Apache","apache"]) in (
        ["Apache"], ["apache"]
    )


def test_special_boundary_behavior_is_unchanged():
    assert matching_keywords(
        {"title":"Campcodes banner.php and ago framework"},
        ["PHP","*go*"]
    ) == []
    assert matching_keywords({"title":"PHP and Go security notice"},["PHP","*go*"]) == ["PHP","*go*"]


def test_no_match_returns_empty_list():
    assert matching_keywords({"title":"Security patch"},["Apache","Redis"]) == []
