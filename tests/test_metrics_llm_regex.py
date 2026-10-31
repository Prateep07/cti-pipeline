from pathlib import Path

import pytest

from cti import baseline_llm, baseline_regex
from cti.data import load_jsonl
from cti.metrics import score

SAMPLE = Path(__file__).parents[1] / "data" / "sample" / "sample_reports.jsonl"


def _it(t, v, quote=""):
    return {"type": t, "value": v, "quote": quote}


# ------------------------------------------------------------------ metrics
def test_perfect_prediction():
    texts = {"d": "C2 at 203.0.113.45 and CVE-2023-23397."}
    gold = {"d": [_it("ipv4", "203.0.113.45"), _it("cve", "CVE-2023-23397")]}
    m = score(gold, gold, texts)
    assert m["micro"]["f1"] == 1.0
    assert m["hallucination"]["rate"] == 0.0


def test_hallucination_is_counted_even_if_it_matches_gold():
    texts = {"d": "C2 at 203.0.113.45."}
    gold = {"d": [_it("ipv4", "203.0.113.45"), _it("ipv4", "198.51.100.9")]}  # gold item not in text
    preds = {"d": [_it("ipv4", "203.0.113.45"), _it("ipv4", "198.51.100.9")]}
    m = score(preds, gold, texts)
    assert m["hallucination"]["n_ungrounded"] == 1
    assert m["hallucination"]["rate"] == 0.5
    assert m["micro"]["tp"] == 2  # matches gold, but still flagged as hallucinated


def test_fp_fn_and_dedupe():
    texts = {"d": "a 203.0.113.45 b 198.51.100.7"}
    gold = {"d": [_it("ipv4", "203.0.113.45")]}
    preds = {"d": [_it("ipv4", "198.51.100.7"), _it("ipv4", "198.51.100.7")]}
    m = score(preds, gold, texts)
    assert (m["micro"]["tp"], m["micro"]["fp"], m["micro"]["fn"]) == (0, 1, 1)


def test_collapse_hosts():
    texts = {"d": "see http://evil.example.com/x"}
    gold = {"d": [_it("url", "http://evil.example.com/x"), _it("domain", "evil.example.com")]}
    preds = {"d": [_it("url", "http://evil.example.com/x")]}
    assert score(preds, gold, texts, collapse_hosts=True)["micro"]["fn"] == 0
    assert score(preds, gold, texts, collapse_hosts=False)["micro"]["fn"] == 1


def test_defanged_prediction_is_relaxed_grounded_not_strict():
    texts = {"d": "C2 evil[.]example[.]com"}
    preds = {"d": [_it("domain", "evil.example.com")]}
    h = score(preds, {"d": []}, texts)["hallucination"]
    assert h["rate"] == 0.0 and h["rate_strict"] == 1.0


# ------------------------------------------------------------------ llm baseline
class Mock:
    name = "mock"

    def __init__(self, out):
        self.out, self.calls = out, 0

    def complete(self, system, user, schema):
        self.calls += 1
        return self.out


def test_llm_parse_and_hallucination_flag():
    text = "C2 at 203.0.113.45 only."
    out = '{"items": [{"type": "ipv4", "value": "203.0.113.45", "quote": "C2 at 203.0.113.45"},' \
          ' {"type": "ipv4", "value": "198.51.100.9", "quote": "scanner 198.51.100.9"}]}'
    items, stats = baseline_llm.extract_llm(text, Mock(out))
    assert len(items) == 2 and stats["parse_failures"] == 0
    h = score({"d": items}, {"d": []}, {"d": text})["hallucination"]
    assert h["n_ungrounded"] == 1 and h["quote_ungrounded_rate"] == 0.5


def test_llm_parse_failure_and_fences_and_invalid_items():
    items, stats = baseline_llm.extract_llm("x", Mock("not json"))
    assert items == [] and stats["parse_failures"] == 1
    fenced = '```json\n{"items": [{"type": "ipv4", "value": "1.2.3.4", "quote": ""}, {"type": "bogus", "value": "z", "quote": ""}]}\n```'
    items, stats = baseline_llm.extract_llm("x", Mock(fenced))
    assert len(items) == 1 and stats["invalid_items"] == 1 and stats["parse_failures"] == 0


def test_llm_cache_avoids_second_call(tmp_path):
    b = Mock('{"items": []}')
    baseline_llm.extract_llm("report", b, cache_dir=tmp_path)
    baseline_llm.extract_llm("report", b, cache_dir=tmp_path)
    assert b.calls == 1


def test_chunking_covers_text_with_overlap():
    text = "\n".join(f"line {i} " + "x" * 50 for i in range(200))
    chunks = baseline_llm.chunk_text(text, max_chars=1000, overlap=100)
    assert len(chunks) > 1
    assert all(len(c) <= 1000 for c in chunks)
    for i in range(200):  # every line fully present in at least one chunk
        assert any(f"line {i} " in c for c in chunks)


# ------------------------------------------------------------------ regex baseline
def test_regex_recovers_gold_on_clean_sample_reports():
    recs = {r["id"]: r for r in load_jsonl(SAMPLE)}
    for doc_id in ("r01", "r02", "r03", "r06"):
        r = recs[doc_id]
        items, backend = baseline_regex.extract(r["text"])
        m = score({doc_id: items}, {doc_id: r["gold"]}, {doc_id: r["text"]})
        assert m["micro"]["fn"] == 0, (doc_id, backend, m["micro"])
        assert m["hallucination"]["rate"] == 0.0


def test_regex_false_positives_on_decoys_are_visible():
    recs = {r["id"]: r for r in load_jsonl(SAMPLE)}
    items, _ = baseline_regex.extract(recs["r08"]["text"])
    assert any(i["type"] == "ipv4" and i["value"] == "3.2.1.7" for i in items)  # version string looks like an IP


def test_explicit_ioc_finder_without_install_raises():
    if baseline_regex.ioc_finder_available():
        pytest.skip("ioc-finder installed")
    with pytest.raises(RuntimeError):
        baseline_regex.extract("x", backend="ioc_finder")
