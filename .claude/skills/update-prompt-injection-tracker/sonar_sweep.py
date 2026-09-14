#!/usr/bin/env python3
"""
sonar_sweep.py — Perplexity Sonar retrieval layer for the Prompt-Injection-in-the-Wild tracker.

WIDE NET: no domain allowlist. Retrieval is scoped only by publication date (--since)
plus an optional tiny spam denylist. Deep-research-heavy by default.

For each thematic query it runs Perplexity `sonar-deep-research` (async) and collects
(a) structured FINDINGS from the model and (b) the real SOURCE reports from the response
`search_results` (never trust model-generated URLs — they hallucinate). Each source is
tagged trusted/untrusted by domain so the skill knows which bypass the vetting gate.

Output: a JSON file the skill (Claude) consumes for trust-tiering, vetting, and parsing.

Env:  PERPLEXITY_API_KEY  (required unless --dry-run)
Usage:
  python sonar_sweep.py --since 2023-09-01 --out candidates.json               # normal monthly
  python sonar_sweep.py --since 2023-09-01 --out candidates.json --backfill    # 2-year seeding budget
  python sonar_sweep.py --since 2023-09-01 --dry-run                           # print payloads, no calls
"""
import argparse, json, os, sys, time, urllib.request, urllib.error
from pathlib import Path

CFG = json.loads((Path(__file__).parent / "config.json").read_text(encoding="utf-8"))
API_BASE = "https://api.perplexity.ai"
TRUSTED = [d.lower() for d in CFG["trusted_sources"]["domains"]]
DENY = [d.lower() for d in CFG["spam_denylist"]["domains"]]

# Wide-net thematic queries. Deep-research fans out its own sub-searches per query; a
# handful of angles covers delivery, encoding, and propagation without an allowlist.
QUERY_TEMPLATES = [
    "Cybersecurity and AI-security reports published on or after {since} documenting a specific, named PROMPT INJECTION "
    "technique against an LLM or LLM-powered agent/assistant. For each, state: how the injected instructions are DELIVERED "
    "to the model (direct prompt, a website the model browses, a document/PDF, an email, retrieved/RAG content, a tool or "
    "function result, an MCP server, or an image/multimodal input); any ENCODING or obfuscation of the payload (Base64, "
    "leetspeak, invisible Unicode tag characters, zero-width characters, homoglyphs, metadata); and which AI MODELS or "
    "products it was confirmed to work against. Name the reporting researcher/organization and the report date. "
    "Include both security-researcher disclosures and in-the-wild cases.",

    "Reports published on or after {since} of INDIRECT prompt injection or tool/agent injection: adversarial instructions "
    "planted in external data (web pages, documents, emails, calendar invites, code/repos, RAG stores) or served through "
    "tool calls, function results, plugins, or Model Context Protocol (MCP) servers, that hijack an LLM agent's behavior. "
    "State the delivery vector, the affected AI model/product, and the reporting org and date.",

    "Reports published on or after {since} of prompt-injection payloads that use ENCODING or OBFUSCATION to evade filters — "
    "Base64, hex, ROT13, leetspeak, invisible Unicode tag characters (U+E0000 range), zero-width characters, homoglyphs, "
    "emoji/variation-selector smuggling, or instructions hidden in HTML/Markdown comments or file/image metadata. "
    "Name the technique, the model it was demonstrated against, and the reporting source and date.",

    "Reports published on or after {since} of PROPAGATING or PERSISTENT prompt injection: AI worms or self-propagating "
    "prompt injections that spread agent-to-agent (e.g. Morris II), payloads that persist in an assistant's long-term or "
    "project MEMORY, injections that spread via a poisoned MCP server to everyone who connects, that move through a chain "
    "of tool calls, or that make an agent send an email/message carrying further instructions. State the propagation "
    "behavior, the affected model/product, and the reporting org and date.",
]

FINDINGS_SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "prompt_injection_candidates",
        "schema": {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "technique_name": {"type": "string", "description": "Short name/label for the technique."},
                            "what_it_does": {"type": "string", "description": "1-3 sentence description of the injection and its effect."},
                            "delivery_method": {"type": "string", "description": "How the injection reaches the model (direct prompt, website, document, email, RAG, tool-call result, MCP server, image, etc.). Leave empty if the report does not state it."},
                            "encoding": {"type": "string", "description": "Obfuscation/encoding of the payload (Base64, leetspeak, invisible Unicode, homoglyphs, etc.). EMPTY if the payload was plain text or the report does not state it. Never guess."},
                            "propagation_behavior": {"type": "string", "description": "Whether/how it spreads or persists (self-propagating worm, persists in memory, spreads via MCP, moves through tool calls, emits an email with further instructions, poisons a shared store). EMPTY if no propagation is reported."},
                            "confirmed_models": {"type": "array", "items": {"type": "string"}, "description": "AI models/products it was EXPLICITLY confirmed to work against. Empty if the report does not name specific models. Never infer."},
                            "attack_source": {"type": "string", "description": "Who originated/demonstrated it: researcher/org name, red team, or in-the-wild threat actor. Empty if not stated."},
                            "evidence_class": {"type": "string", "description": "real in-the-wild use | research/red-team demonstration | vendor advisory | unclear"},
                            "source_report_title": {"type": "string"},
                            "source_publication": {"type": "string", "description": "Reporting org or site name (text, NOT a URL)."},
                            "approx_date": {"type": "string", "description": "Publication date if known, else empty."},
                            "primary_source": {"type": "string", "description": "The org/researcher that ORIGINALLY reported/discovered this, which may differ from an outlet re-reporting it."},
                            "reporting_relationship": {"type": "string", "description": "original primary research | re-reports/cites another named report | unclear"},
                            "cited_prior_reports": {"type": "array", "items": {"type": "string"}, "description": "Titles/orgs this report cites as its source; empty for original research."}
                        },
                        "required": ["technique_name", "what_it_does", "delivery_method", "evidence_class",
                                     "source_report_title", "source_publication",
                                     "primary_source", "reporting_relationship"]
                    }
                }
            },
            "required": ["findings"]
        }
    }
}


def tier_for(url: str) -> str:
    u = (url or "").lower()
    return "trusted" if any(d in u for d in TRUSTED) else "untrusted"


def _post(path, payload, key):
    req = urllib.request.Request(API_BASE + path, data=json.dumps(payload).encode(),
                                 headers={"Authorization": f"Bearer {key}",
                                          "Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())


def _get(path, key):
    req = urllib.request.Request(API_BASE + path,
                                 headers={"Authorization": f"Bearer {key}"}, method="GET")
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())


def since_mdy(iso):
    y, m, d = iso.split("-")
    return f"{int(m)}/{int(d)}/{y}"          # Perplexity wants %m/%d/%Y


def build_body(query, since, model, effort):
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a precise AI-security retrieval assistant specializing in prompt "
             "injection. Return only findings grounded in real, citable reports. Do not invent sources or URLs. Break "
             "each technique into delivery method, encoding, and propagation behavior, and leave any of those EMPTY when "
             "the report does not explicitly state it — never guess. Identify the ORIGINAL primary source of each "
             "technique and whether the reporting outlet is doing original research or re-reporting."},
            {"role": "user", "content": query},
        ],
        "search_after_date_filter": since_mdy(since),
        "response_format": FINDINGS_SCHEMA,
    }
    if model == "sonar-deep-research":
        body["reasoning_effort"] = effort
    if DENY:
        body["search_domain_filter"] = ["-" + d for d in DENY]  # denylist only; NOT an allowlist
    return body


def run_query(query, since, key, model, effort, sync):
    body = build_body(query, since, model, effort)
    if sync or model != "sonar-deep-research":
        resp = _post("/chat/completions", body, key)
    else:
        job = _post("/v1/async/sonar", {"request": body}, key)
        rid = job.get("id") or job.get("request_id") or job.get("job_id")
        if not rid:
            raise RuntimeError(f"async submit returned no id: {json.dumps(job)[:400]}")
        for _ in range(120):                 # poll up to ~10 min
            time.sleep(5)
            st = _get(f"/v1/async/sonar/{rid}", key)
            status = st.get("status", "")
            if status in ("COMPLETED", "completed", "succeeded"):
                resp = st.get("response") or st
                break
            if status in ("FAILED", "failed", "error"):
                raise RuntimeError(f"async job failed: {json.dumps(st)[:400]}")
        else:
            raise TimeoutError(f"async job {rid} did not complete in time")
    return resp


def parse_resp(resp):
    msg = resp["choices"][0]["message"]["content"]
    try:
        findings = json.loads(msg).get("findings", [])
    except Exception:
        findings = [{"technique_name": "PARSE_ERROR", "what_it_does": msg[:500],
                     "delivery_method": "", "evidence_class": "unclear",
                     "source_report_title": "", "source_publication": "",
                     "primary_source": "", "reporting_relationship": "unclear", "cited_prior_reports": []}]
    results = []
    for sr in (resp.get("search_results") or []):
        url = sr.get("url", "")
        results.append({"title": sr.get("title", ""), "url": url,
                        "date": sr.get("date") or sr.get("last_updated", ""),
                        "snippet": sr.get("snippet", ""), "tier": tier_for(url)})
    usage = resp.get("usage", {})
    return findings, results, usage


def est_cost(usage, model):
    if "cost" in usage and isinstance(usage["cost"], (int, float)):
        return float(usage["cost"])
    out = usage.get("completion_tokens", 0) or usage.get("output_tokens", 0)
    reason = usage.get("reasoning_tokens", 0)
    cite = usage.get("citation_tokens", 0)
    searches = usage.get("num_search_queries", usage.get("search_queries", 0))
    return out / 1e6 * 8 + reason / 1e6 * 3 + cite / 1e6 * 2 + searches / 1000 * 5 + 0.5


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", required=True, help="YYYY-MM-DD lower bound on report publication date")
    ap.add_argument("--out", default="candidates.json")
    ap.add_argument("--backfill", action="store_true", help="use the larger one-time backfill budget")
    ap.add_argument("--budget", type=float, default=None)
    ap.add_argument("--model", default=CFG["budget"]["model"])
    ap.add_argument("--effort", default=CFG["budget"]["reasoning_effort"])
    ap.add_argument("--sync", action="store_true", help="use /chat/completions (cheap sonar-pro connectivity test)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    budget = a.budget if a.budget is not None else (CFG["budget"]["backfill_usd"] if a.backfill else CFG["budget"]["per_run_usd"])

    queries = [q.format(since=a.since) for q in QUERY_TEMPLATES]
    if a.dry_run:
        for i, q in enumerate(queries, 1):
            print(f"--- query {i} body ---")
            print(json.dumps(build_body(q, a.since, a.model, a.effort), indent=2)[:1400], "\n")
        print(f"[dry-run] {len(queries)} queries · model={a.model} · budget=${budget} · no API calls made.")
        return

    key = os.environ.get("PERPLEXITY_API_KEY")
    if not key:
        sys.exit("ERROR: PERPLEXITY_API_KEY not set in environment.")

    all_findings, all_results, spend = [], {}, 0.0
    for i, q in enumerate(queries, 1):
        if spend >= budget:
            print(f"[budget] ${spend:.2f} >= ${budget}; stopping before query {i}.", file=sys.stderr)
            break
        try:
            resp = run_query(q, a.since, key, a.model, a.effort, a.sync)
        except Exception as e:
            print(f"[query {i}] error: {e}", file=sys.stderr); continue
        findings, results, usage = parse_resp(resp)
        c = est_cost(usage, a.model); spend += c
        all_findings += findings
        for r in results:
            all_results[r["url"]] = r                     # dedupe sources by URL
        print(f"[query {i}] findings={len(findings)} sources={len(results)} est_cost=${c:.2f} cumulative=${spend:.2f}",
              file=sys.stderr)

    sources = list(all_results.values())
    out = {
        "run_since": a.since, "model": a.model, "queries": len(queries), "backfill": a.backfill,
        "estimated_spend_usd": round(spend, 2), "budget_usd": budget,
        "counts": {"findings": len(all_findings),
                   "sources_trusted": sum(1 for r in sources if r["tier"] == "trusted"),
                   "sources_untrusted": sum(1 for r in sources if r["tier"] == "untrusted")},
        "findings": all_findings,
        "sources": sources,
        "_note": "Reconcile each finding to a real source URL via `sources` (match on title/publication). "
                 "Trusted-tier sources bypass the vetting gate; untrusted go through it. Leave delivery/encoding/"
                 "propagation/models blank in the tracker when a source does not explicitly state them."
    }
    Path(a.out).write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"wrote {a.out}: {out['counts']} · est ${spend:.2f}")


if __name__ == "__main__":
    main()
