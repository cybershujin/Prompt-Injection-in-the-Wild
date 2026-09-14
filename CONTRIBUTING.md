# Contributing

Thanks for helping build **Prompt Injection in the Wild** — an open catalog of publicly reported prompt-injection techniques. Every entry is community-checkable, so a few rules keep it trustworthy.

## The golden rules

1. **Never guess.** Fill a field only if the cited source *explicitly* states it. **Leave anything unstated blank** — a blank means "not stated," never an inferred "none."
2. **Cite the primary source.** Link the report from the researcher/vendor who actually found it, not a news re-write. One primary source per entry.
3. **Be honest about evidence.** Tag **In-the-wild** only when the source reports observed real-world abuse or a real production incident. A researcher/red-team proof-of-concept — *even with a CVE and a vendor fix* — is **Research / red-team** unless in-the-wild abuse was actually observed.
4. **Unclear ≠ dropped.** If a technique is real but its details are vague or unconfirmed, it still belongs here — mark it **Not fully vetted** rather than omitting it.

## How to submit

**Easiest — open an issue.** Use the [**Submit a prompt-injection technique**](../../issues/new?template=new-technique.yml) form; it prompts you for each field. A maintainer converts accepted issues into table rows.

**Or open a pull request.** Add one row to the table in [`README.MD`](README.MD) and (optionally) a row to [`Sources.md`](Sources.md). That's it — **do not edit `index.html`, `tracker.json`, or `stix/prompt-injection-stix2.1.json`**; those are generated from `README.MD` by CI on every merge.

## The schema (one row per technique)

| Column | What goes in it |
|---|---|
| Technique | Short, specific name |
| Delivery Method | How it reaches the model — use the Appendix A terms, `; `-separated |
| Encoding | Payload obfuscation — Appendix B terms; **blank** if plain text / not stated |
| Propagation | Spread/persistence — Appendix C terms; **blank** if none reported |
| Confirmed Models | Models the source explicitly confirms; **blank** if none named |
| Attack Source | `Researcher: … (org)` / `Red team: …` / `In-the-wild: …`; blank if unknown |
| Evidence | `In-the-wild` / `Research / red-team` / `Vendor advisory` / `Unclear` |
| Vetting | `Confirmed` or `Not fully vetted` |
| Brief | 1–3 sentences, plain text (no `|`) |
| ATLAS | MITRE ATLAS ID(s), e.g. `AML.T0051.001`; blank if none applies |
| Reported | Publication month/year, `Mon YYYY`; blank if unknown |
| Link | Primary source URL |

The controlled vocabularies for Delivery / Encoding / Propagation are defined in **Appendices A/B/C** of [`README.MD`](README.MD). If a report needs a genuinely new term, say so — we'll add it to the appendix and credit it.

## What's out of scope

Generic jailbreak wordlists with no delivery/propagation mechanism, pure model-alignment complaints, chatbot *hallucinations* with no injected adversarial instruction, and marketing with no technical substance.
