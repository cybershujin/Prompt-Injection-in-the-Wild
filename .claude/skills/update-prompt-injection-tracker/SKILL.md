---
name: update-prompt-injection-tracker
description: >
  Research and draft an update to the Prompt-Injection-in-the-Wild GitHub tracker. Sweeps new intel
  (Perplexity Sonar deep-research, wide net) for publicly reported prompt-injection techniques, breaks each
  into its three elements (delivery method, encoding, propagation behavior) plus confirmed models, reporting
  source, and attack source, applies a trust-tier + vetting gate, validates MITRE ATLAS IDs, and opens a DRAFT
  pull request for the maintainer. Never guesses a field (blank = not stated); flags unclear entries "Not fully
  vetted"; never merges. Use when asked to "update the prompt injection tracker", run the monthly sweep, or seed
  the initial 2-year backfill.
---

# update-prompt-injection-tracker

Repeatable, human-in-the-loop refresh of [`cybershujin/Prompt-Injection-in-the-Wild`](https://github.com/cybershujin/Prompt-Injection-in-the-Wild).
**Architecture:** Sonar casts a wide net → trust-tiering → vetting gate for untrusted → primary-source resolution / dedup → Claude parses into the 11-column schema → **draft PR** → maintainer approves.
The editorial judgment (is this a real technique, which of delivery/encoding/propagation/models are *explicitly* stated, ATLAS mapping, dedup) stays with Claude + the maintainer — that is the project's value.

**The hard rule: never guess.** Every non-blank cell must come from an explicit statement in the cited source. If a report doesn't state the encoding, the propagation, the confirmed models, or the attack source, **leave that cell blank** (blank = "not stated," never "none"). If the technique itself is vague or unconfirmed, mark **Vetting = `Not fully vetted`** rather than dropping it.

## Inputs & prerequisites
- `PERPLEXITY_API_KEY` in the environment (required for retrieval). Never print, log, or commit it.
- GitHub write auth: `gh` authenticated, or a `GH_TOKEN`/PAT in the environment for headless runs.
- Args: `--since YYYY-MM-DD` (default: repo's last content-update date, see Stage 0; for the initial seed use ~2 years back with `--backfill`). `--budget` (default from `config.json`).
- Files in this skill dir: `config.json`, `sonar_sweep.py`, `monthly_gate.py`, `crosswalk.md`.

## Scheduling gate (monthly runs)
If invoked by the scheduled routine, FIRST run `python monthly_gate.py`. Exit code `10` = not the configured run day → **stop, do nothing**. Exit code `0` = proceed. Manual `/update-prompt-injection-tracker` invocations skip the gate.

## Stage 0 — Baseline & dedupe index
- Fetch live `README.MD` + `Sources.md` from `main` (via `gh api .../contents/...?ref=main`, base64-decode).
- Build a **known-technique index**: every Technique name + the named techniques in `crosswalk.md` (Morris II, EchoLeak, ASCII smuggling, SpAIware/memory persistence, MCP/tool-description poisoning, …).
- Note known source URLs from `Sources.md` (don't re-add existing reports) and a **known-primary-report index** `{researcher/org, technique}` to collapse secondary re-reports.
- Resolve `--since`: default to the newest `Reported` date / last content commit. For the one-time seed, use ~2 years before today + `--backfill`.

## Stage 1 — Retrieval (WIDE NET)
**Preferred (Perplexity Sonar):** if `PERPLEXITY_API_KEY` is set and valid, run
`python sonar_sweep.py --since <SINCE> --out candidates.json` (add `--backfill` for the seed). It writes
`candidates.json` = `{findings[], sources[] (tier: trusted|untrusted), estimated_spend_usd}`. Do NOT trust
model-generated URLs — real URLs are in `sources[]` (from Sonar `search_results`). Reconcile each finding to a
source by matching `source_report_title`/`source_publication` against `sources[].title`/domain.

**Fallback (no/invalid key — e.g. cloud routines where the Perplexity MCP is unavailable):** if the key is
missing or `sonar_sweep.py` returns HTTP 401, retrieve with the built-in **WebSearch + WebFetch** tools instead,
using the same four wide-net angles as `QUERY_TEMPLATES` in `sonar_sweep.py` (general reported PI techniques;
indirect / tool / MCP / agentic delivery; encoding / obfuscation; propagating / persistent). Same discipline
applies: real URLs only, tier each source by domain against `config.json`, and hand survivors to Stage 1.5+.
The rest of the pipeline is identical regardless of which retrieval layer produced the candidates.

## Stage 1.5 — Trust tiering
Split reconciled candidates by source domain (already tagged in `sources[].tier`):
- **Trusted** (AI vendors, Embrace The Red, Simon Willison, HiddenLayer, Lakera, Trail of Bits, PortSwigger, OWASP, NVIDIA, Unit 42, Aim Labs, NCSC/CISA, arXiv-with-caution — see `config.json`) → skip the skeptic, go to Stage 3. Still dedup + bias-flag.
- **Untrusted** (everything else — blogs, news, smaller vendors) → Stage 2.

## Stage 2 — Vetting gate (UNTRUSTED ONLY)
This is a **vetting** gate, not a "reject all research" gate — researcher and red-team disclosures are *in scope* for this tracker. For each untrusted candidate, spawn a **subagent** (Agent tool). It `WebFetch`es the primary source and returns:
1. **Is this a real, described prompt-injection technique?** (vs. a content-free listicle, a duplicate, or something that isn't prompt injection at all).
2. **Which of these are EXPLICITLY stated** in the source: delivery method · encoding · propagation behavior · confirmed models · attack source. Anything not explicitly stated → the corresponding cell stays **blank**.
3. A decision: **`Confirmed`** (real technique, mechanism clear) · **`Not fully vetted`** (real but vague/unconfirmed details) · **`Reject`** (not a PI technique / no substance / pure marketing).
4. **Provenance:** original primary research vs. re-reporting another named report (feeds Stage 2.5).
- `Confirmed` / `Not fully vetted` → Stage 3, carrying the subagent's field-by-field "explicitly stated?" notes and its Vetting decision.
- `Reject` → **"Rejected this cycle"** list: `title · source · url · reason`. Never enters the tracker.
Trusted-source items are NOT gated here, but still get the same **"which fields are explicitly stated"** extraction in Stage 3 (blank the rest).

## Stage 2.5 — Provenance & primary-source resolution (ALL survivors)
1. **Resolve the primary source** from `primary_source` / `reporting_relationship` / `cited_prior_reports` (WebFetch if `unclear`).
2. **Secondary re-report of a KNOWN primary** (match resolved primary against the Stage-0 known-primary-report index; expand via `crosswalk.md`; do NOT rely on the URL):
   - adds no new detail → **DROP**, log under **"Secondary re-reports collapsed"**: `candidate · outlet · url · → maps to <existing row/primary>`.
   - adds new detail (new confirmed model, new delivery vector, new propagation) → propose an **UPDATE** to the existing row.
3. **Provider full-extraction trigger.** If the primary is a `frontier_provider_domains` writeup (Anthropic/OpenAI/Google/Microsoft), WebFetch it and **enumerate every technique it describes**, cross-checking each against the Stage-0 known-technique index. Record found-vs-tracked-vs-new for the PR body.
4. **Original research / genuinely distinct technique** → Stage 3.

## Stage 3 — Parse & normalize into the 12-column schema
For each surviving item, map to: `Technique | Delivery Method | Encoding | Propagation | Confirmed Models | Attack Source | Evidence | Vetting | Brief | ATLAS | Reported | Link`.
- **Controlled vocab.** Map Delivery/Encoding/Propagation to the README Appendix A/B/C terms (`crosswalk.md`), `; `-separated for multiples. If a report needs a genuinely new term, **add it to the appendix** in the PR and use it. **Encoding and Propagation are BLANK unless the source explicitly describes one.**
- **Confirmed Models.** Only models the source explicitly names as confirmed-affected; `; `-separated. Blank otherwise. Never infer "probably all LLMs."
- **Attack Source.** Use the `crosswalk.md` convention (`Researcher: … (org)` / `Red team: …` / `In-the-wild: …`). Blank if unknown.
- **Evidence — scrutinize the in-the-wild claim.** Set from the sweep's `evidence_class`, but VERIFY it against the primary source: use **`In-the-wild`** ONLY when the source explicitly reports observed real-world abuse or a real production incident (name the incident/actor). A working exploit demonstrated by a researcher/red team — even with a CVE and a vendor fix — is **`Research / red-team`**, NOT in-the-wild. Use **`Vendor advisory`** when the affected vendor's own security team is the discloser, and **`Unclear`** when you cannot tell. Do not upgrade a PoC to in-the-wild because it sounds severe; most entries are legitimately Research / red-team.
- **Vetting.** `Confirmed` or `Not fully vetted` from Stage 2 (trusted-source items default `Confirmed` unless their mechanism is unclear). Evidence and Vetting are independent axes — an entry can be `Confirmed` + `Research / red-team`.
- **ATLAS.** Validate every ID against the live ATLAS matrix this run (`crosswalk.md`). Commit only verified IDs; blank if none cleanly applies (note any coined label in the PR body).
- **Reported.** Report **publication** month/year (`Mon YYYY`) from the primary source, with the exact quoted date + URL recorded in the PR body. If unsourced → blank. Date lookups are **best-effort and never block the PR** (one follow-up lookup max, in-line; then write blank and note it).
- **Brief.** 1-3 sentences + inline source link; carry any bias/analyst note.
- **Dedup** against Stage-0 indexes using `crosswalk.md` (match on technique identity + primary-report identity, not URL). Already-tracked technique with fresh reporting → UPDATE, not a new row.

**Pipeline liveness rule (every stage).** Never park the run waiting on a subagent that may not report back. Collect subagents in-line or proceed once their result is merely nice-to-have. If a stage can't complete, **still open the draft PR** with what survived and record the gap under **"Incomplete this cycle."** A partial, clearly-annotated draft PR beats producing nothing.

## Stage 4 — Draft packaging
Write `proposed-update-YYYY-MM.md` (schema-exact, paste-ready), grouped: new rows · updates to existing rows · proposed new Appendix A/B/C terms · new `Sources.md` rows. Each row carries a review-only tag `[vetting · evidence class · which fields are sourced · source date]`, plus the subagent's per-field "explicitly stated?" notes for untrusted items.

## Stage 5 / 6 — Open the DRAFT PR
Create a **`claude/`-prefixed** branch off `main` (e.g. `claude/pi-tracker-YYYY-MM-DD`) — cloud routines may push only to `claude/*` under the default safe permission. Edit **only** `README.MD` (the table + any new appendix terms) + `Sources.md` via the `gh api` blobs→tree→commit→PR flow. **Do NOT edit `index.html` / `tracker.json` / the STIX bundle** — the repo's Action regenerates those on merge. Open the PR with `"draft": true`. The **PR description** carries (all review-only): (1) proposed-rows summary; (2) **"Rejected this cycle"** with reasons; (3) per-field "explicitly stated?" notes + Vetting rationale for untrusted items; (4) date citations (exact quote + URL) for each `Reported` value; (5) **"Secondary re-reports collapsed"**; (6) **"Provider-report completeness check"**; (7) any coined labels / new appendix terms; (8) ATLAS IDs validated this run.
**Never auto-merge. Hold as draft until the maintainer marks it ready.** Post the PR URL back.

## Guardrails
- Draft PR only; never merge; never push to `main`; never edit the generated files.
- Wide-net retrieval; the only list-based step is trust-tiering (skeptic bypass), never retrieval.
- **Never guess a field.** Blank = not stated. Unclear technique = `Not fully vetted`, not dropped and not fabricated.
- Reject only genuine non-techniques / substanceless marketing (log them in the PR, not the tracker).
- Enumerate every technique in a provider/multi-technique report; collapse secondary re-reports on primary-report identity.
- Commit only ATLAS IDs verified against the live matrix this run.
- Respect the `--budget` guard and the Perplexity dashboard spend cap. Never expose the API key.
