# CTI extraction: Week 2 baselines

## Data format
One JSON object per line:

    {"id": "r01", "source": "vendor-x", "campaign": "alpha", "text": "...",
     "gold": [{"type": "ipv4", "value": "203.0.113.45"}, ...]}

Types: ipv4, ipv6, domain, url, email, md5, sha1, sha256, cve, attack_technique.
`data/sample/sample_reports.jsonl` is a synthetic 8-report smoke-test set (documentation IP ranges and
example domains only). It is for testing the code, not for reporting results.

## Commands

    pip install -r requirements.txt
    python -m pytest -q

    # leakage-safe split (by campaign; use --key source to group by publisher instead)
    python -m cti.data split --input data/all.jsonl --outdir data/splits --seed 13

    # regex baseline (uses ioc-finder if installed, otherwise a built-in fallback, recorded in the output)
    python -m cti.run_baseline --method regex --data data/splits/test.jsonl --out results/regex_test.json

    # zero-shot LLM baseline
    export ANTHROPIC_API_KEY=...
    python -m cti.run_baseline --method llm --backend anthropic --model <model-id> \
        --data data/splits/test.jsonl --out results/zeroshot_test.json

    # local open model behind a vLLM / Ollama OpenAI-compatible server
    python -m cti.run_baseline --method llm --backend openai_compat --base-url http://localhost:8000/v1 \
        --model <served-name> --data data/splits/test.jsonl --out results/zeroshot_local_test.json

Each run writes `<out>.json` (config, metrics, run stats) and `<out>.preds.jsonl` (per-report
predictions next to gold, for error analysis). LLM responses are cached in `results/cache`.

## Metric definitions (state these in the paper)
- Items are (type, normalised value) pairs, deduplicated per report; P/R/F1 are micro-averaged.
- Hallucination rate = predicted items whose value is not found in the report text, measured before any gold
  comparison. `rate` refangs and lower-cases first (primary); `rate_strict` is character-for-character.
- `collapse_hosts` (default on) drops a domain/IP that is only the host of a URL/email in the same report,
  from both prediction and gold. Disable with `--no-collapse-hosts`.
- LLM runs also report `parse_failures` and `invalid_items`; a parse failure counts as missed items, so report it.
