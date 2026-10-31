"""Extraction metrics and hallucination rate.

Matching: an item is a (type, normalised value) pair; duplicates within a report count once.
Precision / recall / F1 are micro-averaged over the whole split (zero-division -> 0.0).

Hallucination rate = fraction of predicted items whose value does not appear in the report text.
  rate         relaxed check (after refanging and lower-casing)   <- primary
  rate_strict  character-for-character check in the raw text
It is measured on predictions BEFORE any gold comparison, so a hallucinated item that happens to
match gold still counts as hallucinated.

collapse_hosts (default on): a domain/IP that is just the host of a URL or email address in the same
report is dropped from BOTH prediction and gold before scoring. This removes the annotation-convention
difference "does evil.com inside http://evil.com/x count as a separate domain?".
"""
from __future__ import annotations

import re
from collections import Counter

from .normalize import grounded, normalize_value, quote_grounded
from .schema import IOC_TYPES

_URL_HOST = re.compile(r"^[a-z][a-z0-9+.-]*://(?:[^/?#@]*@)?(\[[^\]]+\]|[^/?#:]+)")


def _key(item: dict) -> tuple[str, str]:
    return item["type"], normalize_value(item["type"], item["value"])


def _host_of(type_: str, norm_value: str) -> str | None:
    if type_ == "url":
        m = _URL_HOST.match(norm_value.lower())
        return m.group(1).strip("[]") if m else None
    if type_ == "email":
        return norm_value.rsplit("@", 1)[-1].lower()
    return None


def _collapse(keys: set) -> set:
    hosts = {h for t, v in keys if (h := _host_of(t, v))}
    return {(t, v) for t, v in keys if not (t in ("domain", "ipv4", "ipv6") and v.lower() in hosts)}


def _prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": p, "recall": r, "f1": f, "tp": tp, "fp": fp, "fn": fn}


def _rate(num: int, den: int):
    return num / den if den else None


def score(preds: dict, gold: dict, texts: dict, collapse_hosts: bool = True) -> dict:
    """preds/gold: {doc_id: [{"type","value",...}]}; texts: {doc_id: report text}."""
    tp, fp, fn = Counter(), Counter(), Counter()
    n_pred, n_ung, n_ung_strict = Counter(), Counter(), Counter()
    q_total = q_ung = 0

    for doc_id, text in texts.items():
        unique: dict[tuple, dict] = {}
        for it in preds.get(doc_id, []):
            if it.get("type") in IOC_TYPES and it.get("value"):
                unique.setdefault(_key(it), it)

        for (t, _), it in unique.items():
            n_pred[t] += 1
            strict, relaxed = grounded(t, it["value"], text)
            n_ung[t] += not relaxed
            n_ung_strict[t] += not strict
            if it.get("quote"):
                q_total += 1
                q_ung += not quote_grounded(it["quote"], text)

        pk = set(unique)
        gk = {_key(g) for g in gold.get(doc_id, []) if g.get("type") in IOC_TYPES}
        if collapse_hosts:
            pk, gk = _collapse(pk), _collapse(gk)
        for t, _ in pk & gk:
            tp[t] += 1
        for t, _ in pk - gk:
            fp[t] += 1
        for t, _ in gk - pk:
            fn[t] += 1

    per_type = {}
    for t in IOC_TYPES:
        if tp[t] or fp[t] or fn[t] or n_pred[t]:
            per_type[t] = {
                **_prf(tp[t], fp[t], fn[t]),
                "n_pred": n_pred[t],
                "hallucination_rate": _rate(n_ung[t], n_pred[t]),
            }

    total_pred = sum(n_pred.values())
    return {
        "n_docs": len(texts),
        "collapse_hosts": collapse_hosts,
        "micro": _prf(sum(tp.values()), sum(fp.values()), sum(fn.values())),
        "per_type": per_type,
        "hallucination": {
            "n_pred": total_pred,
            "n_ungrounded": sum(n_ung.values()),
            "rate": _rate(sum(n_ung.values()), total_pred),
            "n_ungrounded_strict": sum(n_ung_strict.values()),
            "rate_strict": _rate(sum(n_ung_strict.values()), total_pred),
            "quotes_checked": q_total,
            "quote_ungrounded_rate": _rate(q_ung, q_total),
        },
    }


def _fmt(x) -> str:
    return "  n/a" if x is None else f"{x:.3f}"


def format_report(m: dict) -> str:
    lines = [f"{'type':<17}{'P':>7}{'R':>7}{'F1':>7}{'TP':>5}{'FP':>5}{'FN':>5}{'halluc':>8}"]
    for t, v in m["per_type"].items():
        lines.append(
            f"{t:<17}{v['precision']:>7.3f}{v['recall']:>7.3f}{v['f1']:>7.3f}"
            f"{v['tp']:>5}{v['fp']:>5}{v['fn']:>5}{_fmt(v['hallucination_rate']):>8}"
        )
    mi, h = m["micro"], m["hallucination"]
    lines.append(
        f"{'MICRO':<17}{mi['precision']:>7.3f}{mi['recall']:>7.3f}{mi['f1']:>7.3f}"
        f"{mi['tp']:>5}{mi['fp']:>5}{mi['fn']:>5}{_fmt(h['rate']):>8}"
    )
    lines.append(
        f"hallucination: {h['n_ungrounded']}/{h['n_pred']} ungrounded (relaxed), "
        f"{h['n_ungrounded_strict']}/{h['n_pred']} (strict); quote ungrounded rate {_fmt(h['quote_ungrounded_rate']).strip()}"
    )
    return "\n".join(lines)
