"""Run a baseline on a split and write metrics + per-report predictions.

Examples
  python -m cti.run_baseline --method regex --data data/splits/test.jsonl --out results/regex_test.json
  python -m cti.run_baseline --method llm --backend anthropic --model <model-id> \
      --data data/splits/test.jsonl --out results/zeroshot_test.json
  python -m cti.run_baseline --method llm --backend openai_compat --base-url http://localhost:8000/v1 \
      --model <served-model-name> --data data/splits/test.jsonl --out results/zeroshot_local_test.json
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import baseline_llm, baseline_regex
from .data import load_jsonl, save_jsonl
from .metrics import format_report, score


def _temp(s: str):
    return None if s.lower() == "none" else float(s)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--method", required=True, choices=["regex", "llm"])
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--regex-backend", default="auto", choices=["auto", "ioc_finder", "fallback"])
    ap.add_argument("--backend", choices=["anthropic", "openai_compat"])
    ap.add_argument("--model")
    ap.add_argument("--base-url")
    ap.add_argument("--temperature", type=_temp, default=0.0, help="float, or 'none' to omit the parameter")
    ap.add_argument("--cache-dir", default="results/cache")
    ap.add_argument("--no-collapse-hosts", action="store_true")
    args = ap.parse_args()

    records = load_jsonl(args.data)
    missing = [r["id"] for r in records if "gold" not in r]
    if missing:
        raise SystemExit(f"records without gold labels: {missing[:5]}")

    config = {
        "method": args.method,
        "data": args.data,
        "n_docs": len(records),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "collapse_hosts": not args.no_collapse_hosts,
    }

    if args.method == "regex":
        used = set()

        def extractor(text):
            items, backend = baseline_regex.extract(text, args.regex_backend)
            used.add(backend)
            return items, {}

    else:
        if not (args.backend and args.model):
            raise SystemExit("--method llm needs --backend and --model")
        backend = baseline_llm.make_backend(args.backend, args.model, args.base_url, args.temperature)
        config.update(llm_backend=backend.name, model=args.model)

        def extractor(text):
            return baseline_llm.extract_llm(text, backend, cache_dir=args.cache_dir)

    preds, stats = {}, Counter()
    for i, rec in enumerate(records, 1):
        items, st = extractor(rec["text"])
        preds[rec["id"]] = items
        stats.update({k: v for k, v in st.items() if isinstance(v, (int, float))})
        if i % 10 == 0 or i == len(records):
            print(f"  {i}/{len(records)} reports", flush=True)

    if args.method == "regex":
        config["regex_backend"] = sorted(used)[0] if len(used) == 1 else sorted(used)
        config["ioc_finder_version"] = baseline_regex.ioc_finder_version()
        if config["regex_backend"] == "fallback":
            print("WARNING: ioc-finder not used - these are built-in fallback regex numbers, not ioc-finder.")

    metrics = score(
        preds,
        {r["id"]: r["gold"] for r in records},
        {r["id"]: r["text"] for r in records},
        collapse_hosts=not args.no_collapse_hosts,
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"config": config, "stats": dict(stats), "metrics": metrics}, indent=2))
    save_jsonl(out.with_suffix(".preds.jsonl"), [{"id": r["id"], "pred": preds[r["id"]], "gold": r["gold"]} for r in records])

    print(format_report(metrics))
    if stats:
        print("run stats:", dict(stats))
    print(f"wrote {out} and {out.with_suffix('.preds.jsonl')}")


if __name__ == "__main__":
    main()
