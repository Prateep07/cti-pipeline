"""Dataset I/O and leakage-safe splitting.

Record format (one JSON object per line):
  {"id": str, "source": str, "campaign": str, "text": str,
   "gold": [{"type": <IOC_TYPES>, "value": str}, ...]}

Splits are made by GROUP (campaign by default, falling back to source, then id), so reports
about the same campaign never land in different splits. Near-duplicate reports (vendors
republishing the same story) are checked across splits as a second leakage guard.
"""
from __future__ import annotations

import argparse
import json
import random
import re
from collections import defaultdict
from pathlib import Path


def load_jsonl(path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def save_jsonl(path, records) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def group_of(rec: dict, key: str = "campaign") -> str:
    return rec.get(key) or rec.get("source") or rec["id"]


def group_split(records, ratios=(0.7, 0.15, 0.15), seed: int = 13, key: str = "campaign"):
    """Assign whole groups to train/val/test, approximating the requested document ratios."""
    names = ("train", "val", "test")
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        groups[group_of(r, key)].append(r)

    order = sorted(groups)
    random.Random(seed).shuffle(order)
    order.sort(key=lambda g: -len(groups[g]))  # largest groups first; ties keep the shuffled order

    targets = [ratio * len(records) for ratio in ratios]
    sizes = [0, 0, 0]
    splits: dict[str, list[dict]] = {n: [] for n in names}
    assignment: dict[str, str] = {}
    for g in order:
        i = max(range(3), key=lambda j: targets[j] - sizes[j])
        splits[names[i]].extend(groups[g])
        sizes[i] += len(groups[g])
        assignment[g] = names[i]

    manifest = {
        "seed": seed,
        "group_key": key,
        "ratios": list(ratios),
        "counts": {n: len(splits[n]) for n in names},
        "n_groups": len(groups),
        "groups": assignment,
    }
    return splits, manifest


def _shingles(text: str, n: int = 5) -> set[str]:
    words = re.findall(r"\w+", text.lower())
    return {" ".join(words[i : i + n]) for i in range(max(1, len(words) - n + 1))}


def near_duplicates(a: list[dict], b: list[dict], threshold: float = 0.8):
    """Pairs (id_a, id_b, jaccard) of reports across two splits with word 5-gram Jaccard >= threshold."""
    sb = [(r["id"], _shingles(r["text"])) for r in b]
    out = []
    for r in a:
        sa = _shingles(r["text"])
        for bid, s in sb:
            union = len(sa | s)
            if union and len(sa & s) / union >= threshold:
                out.append((r["id"], bid, round(len(sa & s) / union, 3)))
    return out


def _cli_split(args) -> None:
    records = load_jsonl(args.input)
    splits, manifest = group_split(records, seed=args.seed, key=args.key)
    outdir = Path(args.outdir)
    for name, recs in splits.items():
        save_jsonl(outdir / f"{name}.jsonl", recs)
        if not recs:
            print(f"WARNING: split '{name}' is empty - too few groups for these ratios")

    leaks = []
    for tr_name, te_name in (("train", "test"), ("train", "val"), ("val", "test")):
        for pair in near_duplicates(splits[tr_name], splits[te_name], args.dup_threshold):
            leaks.append({"a_split": tr_name, "b_split": te_name, "pair": pair})
    manifest["near_duplicate_pairs_across_splits"] = leaks
    (outdir / "manifest.json").write_text(json.dumps(manifest, indent=2))

    print(f"groups={manifest['n_groups']}  counts={manifest['counts']}")
    if leaks:
        print(f"WARNING: {len(leaks)} near-duplicate pair(s) across splits (see manifest.json) - merge their groups")
    else:
        print("no near-duplicate leakage detected across splits")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("split", help="group-aware train/val/test split")
    s.add_argument("--input", required=True)
    s.add_argument("--outdir", required=True)
    s.add_argument("--key", default="campaign", choices=["campaign", "source"])
    s.add_argument("--seed", type=int, default=13)
    s.add_argument("--dup-threshold", type=float, default=0.8)
    s.set_defaults(func=_cli_split)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
