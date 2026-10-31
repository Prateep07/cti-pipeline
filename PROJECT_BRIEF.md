# Project brief (handoff for another AI agent)

## 1. What this project is
**Title:** Mitigating poisoning and hallucination attacks in LLM-based Cyber Threat Intelligence (CTI) pipelines.

The user is a student building this as **both a research paper and a course project**, with a hard deadline of
**2 months** (started 2026-10-31; today at time of writing). Scope was deliberately cut to fit that.

**Core idea:** CTI reports (vendor blogs, advisories) are processed by an LLM to extract indicators of compromise (IOCs)
and ATT&CK technique IDs. That extractor is itself an attack surface:
- **Hallucination (Fidelity failure):** the model invents IPs, hashes, CVEs, or technique IDs not present in the source text. A fabricated IOC that reaches a blocklist or SIEM causes false alarms and alert fatigue.
- **Input poisoning (Integrity failure):** an attacker publishes reports containing fake IOCs, benign infrastructure (e.g. Google DNS, Microsoft) framed as malicious to cause denial-of-service blocklisting, contradictory claims, or hidden prompt-injection instructions.
- **Training-data poisoning** (secondary): mislabeled or backdoored samples in fine-tuning data.

**Key Conceptual Distinction (Core to the paper framing):**
- **Grounding handles hallucination (fidelity):** Programmatic verification and verbatim quotes prove the model did not invent text out of thin air. However, **grounding does NOT stop in-text poisoning** because an attacker-injected fake IOC appears verbatim in the text and will pass grounding with a 100% score.
- **Structural sanitization, semantic role tagging, and quarantine handle poisoning (integrity):** Defending against poisoning requires stripping hidden injection channels, strict untrusted-data encapsulation, extracting the semantic role (`malicious` vs `benign_utility`), and cross-source corroboration.
- The user's original idea was "fine-tune an LLM to strictly extract useful info". **The extractor is the thing to defend, not the defense.**

## 2. Planned contributions (paper framing)
1. A threat model and a **reproducible attack benchmark** for LLM-based CTI extraction that tests both unfaithful hallucinations and adversarial in-text poisoning.
2. A **grounded and sanitized extractor pipeline** (small open model, QLoRA, strict JSON output where every item carries a verbatim source quote and semantic role) wrapped in layered defenses.
3. An empirical study of **how much each defense layer reduces hallucination rate and attack success rate (ASR), and at what cost to recall**, using ablations and adaptive attacks.

**Research questions**
- RQ1: How much do hallucination and adversarial poisoning degrade a baseline CTI extractor?
- RQ2: Does grounded extraction plus verbatim verification reduce the hallucination rate without destroying recall?
- RQ3: Do structural sanitization, semantic role attribution, and corroboration reduce poisoning and prompt injection success?

## 3. Scope (cut for 2 months)
- Entity types:
  - **Lexical IOCs:** `ipv4`, `ipv6`, `domain`, `url`, `email`, `md5`, `sha1`, `sha256`, `cve` (evaluated via lexical/surface string grounding).
  - **Semantic TTPs:** `attack_technique` (MITRE ATT&CK technique IDs). Note: ATT&CK techniques are semantic concepts, not pure lexical strings; reports often describe techniques in prose without explicit IDs. They must be evaluated using semantic matching / mapping accuracy rather than purely penalizing them under literal string grounding.
- **One** open 7-8B model fine-tuned with QLoRA, plus one zero-shot baseline. No multi-model sweep.
- **Dataset acquisition (CRITICAL PATH):** Use an existing annotated CTI dataset (e.g., AnnoCTR, MITRE TRAM, CTINexus-related data, or APTnotes) plus a small self-labeled set (about 40-60 reports). Securing and converting this dataset is the immediate blocker.
- Training-data poisoning: at most one experiment (one rate, e.g. 5%), otherwise future work.
- Corroboration across sources: a small or simulated version only.
- Output validated JSON; STIX 2.1 mapping is an export step, not core.

## 4. Defense pipeline (target design, built in Week 6)
The defense pipeline separates fidelity checks from integrity checks across distinct, ablatable layers:

1. **Structural Sanitization & Untrusted Data Encapsulation (Anti-Injection):**
   - Strip hidden channels (HTML comments `<!-- ... -->`, markdown image tags, zero-width spaces, suspicious control characters).
   - Strict delimitation: encapsulate the report inside `<untrusted_cti_report>` tags and instruct the model that content within is passive data, never instructions.
2. **Constrained Extraction & Semantic Role Attribution:**
   - Strict JSON schema output requiring a verbatim `quote`.
   - Extract semantic role/intent: flag whether an indicator is an active threat (`c2`, `payload_delivery`) or an incidental/benign utility (`benign_reference`, `connectivity_check`).
   - The model may abstain (return an empty list).
3. **Deterministic Verification & Benign Quarantine:**
   - **Grounding check (for hallucination):** Value and quote must appear in the source text (boundary-aware regex and refanging).
   - Format validation (valid IP ranges, hash lengths, CVE formats).
   - **Benign quarantine (for DoS poisoning):** Well-known infrastructure (RFC 1918 private IPs, major public DNS like 8.8.8.8, top-level benign domains) are quarantined for analyst review rather than auto-blocklisted.
4. **Self-consistency & Isolated Verification:**
   - Run $N=3\text{--}5$ samples or pass isolated `(quote, indicator)` pairs to a fresh verification prompt to filter stochastic hallucinations and context-wide injection tricks.
5. **Multi-source Corroboration (Optional / Simulated):**
   - Assign confidence scores based on cross-vendor agreement before promoting an indicator to a high-confidence blocklist.

Each layer must be modular so ablation studies can measure the marginal benefit of each defense.

## 5. Timeline (8 weeks)
| Week | Work | Status |
|---|---|---|
| 1 | Scoping, 10-15 papers, gap + RQs, dataset access, one-page threat model | **Not done by the assistant; user's responsibility** |
| 2 | Group-aware split, regex baseline (ioc-finder), zero-shot LLM baseline, metrics incl. hallucination rate | **Code written and unit-tested on synthetic data; needs real dataset run** |
| 3 | Attack benchmark: fake/benign-as-malicious IOC injection, prompt-injection payloads in comments/footnotes, contradictory report pairs; measure ASR on baselines (motivating RQ1) | **Next** |
| 4-5 | QLoRA fine-tune of grounded extractor with abstention examples | |
| 6 | Layered defenses (sanitizer, role attribution, quarantine filter, verifier) | |
| 7 | Full evaluation grid, ablations, 3 seeds, error analysis | |
| 8 | Paper + course deliverables, 3-4 days buffer | |

Fallback if fine-tuning slips: few-shot prompting plus the verification/sanitization layers; the benchmark and defense contribution still stand. Include adaptive attacks (e.g. a fake IOC that *does* appear verbatim in the report, which the grounding check cannot catch) and report that limit honestly.

## 6. Current code (repo `cti_pipeline/`)
    cti/schema.py          IOC_TYPES, pydantic ExtractedItem/Extraction, strict JSON schema dict
    cti/normalize.py       refang(), normalize_value(), grounded() -> (strict, relaxed), quote_grounded()
    cti/data.py            load/save jsonl, group_split(), near_duplicates(), CLI: python -m cti.data split
    cti/baseline_regex.py  ioc-finder adapter + built-in fallback regex extractor
    cti/baseline_llm.py    zero-shot prompt, Anthropic + OpenAI-compatible backends, chunking, disk cache, parse_response
    cti/metrics.py         score(), format_report()
    cti/run_baseline.py    CLI runner (writes <out>.json and <out>.preds.jsonl)
    data/sample/           8 synthetic reports (documentation IP ranges, example domains) for smoke tests only
    tests/                 19 passing tests (pytest; run from project root with python -m pytest)
    README.md              commands and metric definitions

**Data format (JSONL):** `{"id","source","campaign","text","gold":[{"type","value"}]}`.

**Metric definitions & evaluation logic**
- **Lexical IOCs:** Evaluated as (type, normalized value) pairs, deduplicated per report; P/R/F1 micro-averaged over the split.
- **ATT&CK techniques:** Semantic mapping evaluation; technique descriptions in prose should not be penalized by string-matching grounding when correctly identified.
- **Hallucination rate:** Predicted items whose value is not found in the report text, computed *before* comparing to gold. `rate` = after refanging and lower-casing (primary); `rate_strict` = character-for-character.
- `collapse_hosts` (default on): Drops domains/IPs that are merely hosts of URLs/emails in the same report from both prediction and gold.
- LLM runs report `parse_failures` and `invalid_items`.

**Deliberate design decision:** The zero-shot baseline prompt has NO injection warnings or defenses, so Week 3 measures the undefended baseline. Defenses are added in Week 6.

## 7. Honest status and known gaps (do not gloss over these)
- **CRITICAL BOTTLENECK - Dataset Missing:** Only 8 synthetic smoke-test reports exist in `data/sample/`. No real dataset has been converted to `data/all.jsonl`. This must be solved immediately to enable Week 3 attacks and Weeks 4-5 fine-tuning.
- `ioc-finder` could not be installed in the authoring sandbox (no PyPI route). The adapter in `baseline_regex.py` is written from documented keys and needs a real installation verification. The built-in fallback regex has false positives on version numbers (e.g. `3.2.1.7`) and private IPs.
- LLM backends (Anthropic tool call, OpenAI-compatible JSON schema) need smoke tests on real reports.
- Prompt injection and semantic poisoning defenses do not exist in the current baseline (by design for Week 2, to be built in Week 6).

## 8. Immediate next steps
1. **Acquire & convert real dataset:** Select an open CTI corpus, convert to JSONL format, and run `python -m cti.data split`.
2. Install `ioc-finder`, run tests, and run the regex baseline on the real test split.
3. Run the zero-shot LLM baseline on the real test split; check parse failures and initial hallucination rate.
4. **Week 3 Attack Benchmark:** Implement scripted, seeded attack generators (fake IOC injection, benign-as-malicious framing, prompt injections in hidden comments/tags) to measure baseline Attack Success Rate (ASR).
5. **Week 6 Defenses:** Implement structural input sanitization, semantic role attribution in the schema, and benign quarantine filters.

## 9. Guidance for the agent
- Maintain the clear academic boundary: Grounding defends against hallucination (fidelity); sanitization, role attribution, and quarantine defend against poisoning (integrity).
- Prefer small, tested, reproducible steps; one codebase and one results table should serve both the paper and the course report.
- Be explicit about what was run versus only written. Verify time-sensitive information (datasets, recent 2024-2026 CTI papers).
- This work is strictly defensive. Attack generators exist solely in a local sandbox to evaluate the pipeline's defensive boundaries.
