import os
os.environ.setdefault("API_TOKEN","test-only")
from app.worker import matches, same_strings

def test_blacklist_only_title():
    assert not matches({"key":"k","title":"Spring RCE","description":"x"},True,["spring"],[])
    assert matches({"key":"k","title":"Other","description":"spring"},True,["spring"],[])

def test_whitelist_matches_description():
    assert matches({"key":"k","title":"Other","description":"Spring vulnerability"},True,[],["spring"])
    assert not matches({"key":"k","title":"Other","description":"Nothing"},True,[],["spring"])

def test_provider_value_required():
    assert not matches({"key":"k","title":"x"},False)
    assert not matches({"title":"x"},True)

def test_tag_semantics():
    assert same_strings(["a","b"],["b","a"])
    assert not same_strings(["a"],["b"])
