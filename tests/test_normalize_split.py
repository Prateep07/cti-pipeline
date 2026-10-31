from pathlib import Path

from cti.data import group_of, group_split, load_jsonl, near_duplicates
from cti.normalize import grounded, normalize_value, quote_grounded, refang

SAMPLE = Path(__file__).parents[1] / "data" / "sample" / "sample_reports.jsonl"


def test_refang():
    assert refang("hxxps://evil[.]example[.]com") == "https://evil.example.com"
    assert refang("a[at]b(.)c") == "a@b.c"
    assert refang("hxxp[:]//x[.]com") == "http://x.com"


def test_normalize():
    assert normalize_value("cve", "cve-2023-23397") == "CVE-2023-23397"
    assert normalize_value("domain", "Evil[.]Example[.]COM.") == "evil.example.com"
    assert normalize_value("url", "HXXP://Evil[.]com/Path") == "http://evil.com/Path"


def test_grounded_defanged_is_relaxed_only():
    text = "C2: hxxp://a[.]example[.]com/x"
    strict, relaxed = grounded("url", "http://a.example.com/x", text)
    assert (strict, relaxed) == (False, True)
    # copying verbatim, defanged, is grounded under both criteria
    assert grounded("url", "hxxp://a[.]example[.]com/x", text) == (True, True)


def test_grounding_respects_boundaries():
    assert grounded("ipv4", "1.2.3.4", "seen 11.2.3.45 today") == (False, False)
    assert grounded("ipv4", "1.2.3.4", "seen 1.2.3.4.5 today") == (False, False)
    assert grounded("ipv4", "203.0.113.45", "C2 is 203.0.113.45.") == (True, True)
    assert grounded("attack_technique", "T1059", "used T1059.001 here") == (False, False)


def test_quote_grounded():
    text = "The loader contacts the C2 server\nat 203.0.113.45 over HTTPS."
    assert quote_grounded("C2 server at 203.0.113.45", text)
    assert not quote_grounded("C2 server at 203.0.113.99", text)


def test_split_has_no_group_leakage_and_is_deterministic():
    recs = load_jsonl(SAMPLE)
    splits, manifest = group_split(recs, seed=1)
    seen = {}
    for name, rs in splits.items():
        for r in rs:
            assert seen.setdefault(group_of(r), name) == name
    assert sum(len(v) for v in splits.values()) == len(recs)
    again, _ = group_split(recs, seed=1)
    assert {k: [r["id"] for r in v] for k, v in splits.items()} == {k: [r["id"] for r in v] for k, v in again.items()}
    assert manifest["n_groups"] == 6


def test_near_duplicates_detected():
    a = [{"id": "a", "text": "the quick brown fox jumps over the lazy dog near the river bank today"}]
    b = [{"id": "b", "text": "the quick brown fox jumps over the lazy dog near the river bank today"}]
    c = [{"id": "c", "text": "completely different words about ransomware and phishing infrastructure here"}]
    assert near_duplicates(a, b)[0][:2] == ("a", "b")
    assert near_duplicates(a, c) == []
