# Crosswalk — prompt injection → MITRE ATLAS, controlled vocab, dedup notes

Living reference for the sweep. Validate ATLAS IDs against the live matrix
(https://atlas.mitre.org/) every run; extend the vocab lists when a report describes a
genuinely new vector (mirror the extension into README Appendices A/B/C in the PR).

## MITRE ATLAS technique mapping

Prompt-injection reporting maps most often to these ATLAS techniques. **Confirm the exact
ID and title on atlas.mitre.org each run — ATLAS is revised and IDs shift.** Do not commit
an ATLAS ID you did not verify this cycle; leave the ATLAS cell blank if unsure.

| Concept in a report | Likely ATLAS technique (verify each run) |
|---|---|
| Prompt injection (general) | `AML.T0051` LLM Prompt Injection |
| Direct prompt injection | `AML.T0051.000` Direct |
| Indirect prompt injection (data-borne) | `AML.T0051.001` Indirect |
| Jailbreak / guardrail bypass | `AML.T0054` LLM Jailbreak |
| Payload obfuscation / encoding to evade filters | verify — may fall under prompt-injection sub-technique or an obfuscation technique |
| Plugin / tool / connector compromise | verify current ATLAS ID for LLM plugin/tool compromise |
| Data exfiltration via the model | verify current ATLAS ID for LLM-driven exfiltration / data leakage |
| Agent hijack via poisoned external content | `AML.T0051.001` Indirect (delivery) + the relevant impact technique |

If a behavior has **no clean ATLAS mapping**, leave the ATLAS cell blank and note a coined
label in the PR body with `CREDIT: Rachel James, based on <report>` — do not invent an ATLAS ID.

## Delivery methods (README Appendix A) — controlled vocab
Direct prompt · Indirect – website / HTML · Indirect – document / file · Indirect – email ·
Indirect – RAG / retrieved content · Tool-call / function result · MCP server / connection ·
Multimodal – image · Multimodal – audio · Code / repository content · Calendar / invite

## Encodings (README Appendix B) — controlled vocab (BLANK = plain text / not stated)
Base64 · Hex · ROT13 · Leetspeak · Unicode tag characters (invisible) · Zero-width characters ·
Homoglyphs · Emoji / variation-selector smuggling · HTML / Markdown comment · Metadata / EXIF · Multi-layer

## Propagation behaviors (README Appendix C) — controlled vocab (BLANK = none reported)
Self-propagating / worm (AI-to-AI) · Persists in agent / project memory · Spreads via MCP to connectors ·
Moves through tool-call chain · Emits outbound email / message with further instructions ·
Poisons shared data store / RAG · Cross-agent / cross-session

## Dedup notes
- Techniques are often re-reported by multiple outlets. Dedup on **primary-report identity**
  (original researcher/org + the technique), NOT on the retrieved URL. A news outlet re-quoting
  an Embrace The Red post is not a new technique.
- Well-known named techniques to recognize as already-tracked once entered (so re-reports collapse):
  Morris II (self-propagating AI worm), EchoLeak (M365 Copilot zero-click), ASCII smuggling /
  invisible Unicode tag injection, ChatGPT memory persistence ("SpAIware"), tool/MCP description
  poisoning. Keep this list current as rows are added.
- Same technique, materially new detail (new confirmed model, new delivery vector, new propagation)
  → propose an UPDATE to the existing row, not a new row.

## Attack-source convention
Prefix the Attack Source cell so origin type is legible:
`Researcher: <name> (<org>)` · `Red team: <org>` · `In-the-wild: <actor>` · leave blank if unknown.

## Evidence class (controlled) — the in-the-wild vs. research axis
Scrutinize this against the primary source; it is independent of Vetting.
- **In-the-wild** — the source explicitly reports observed real-world abuse or a real production incident (name it). NOT just a severe-sounding PoC.
- **Research / red-team** — a security-researcher or red-team demonstration / responsible disclosure. A working exploit with a CVE and a vendor patch is STILL Research / red-team unless in-the-wild abuse was observed. This is the default for most prompt-injection reporting.
- **Vendor advisory** — disclosed by the affected vendor's own security/red team.
- **Unclear** — cannot determine from the source.
Never upgrade a PoC to In-the-wild for impact; require an explicit real-world-abuse statement.
