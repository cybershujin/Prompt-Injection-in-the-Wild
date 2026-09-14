#!/usr/bin/env python3
"""
build_exports.py — deterministic generator for the Prompt-Injection-in-the-Wild tracker.

Single source of truth: README.MD (Markdown tables + Appendices A/B/C).
This script parses it and emits three derived, version-controlled artifacts:

  - tracker.json                        normalized machine-readable data
  - stix/prompt-injection-stix2.1.json  STIX 2.1 bundle (techniques as attack-patterns)
  - index.html                          self-contained dashboard (GitHub Pages homepage)

Design goals (mirrors the sibling AI-threat-actor tracker generator):
  * stdlib only — runs on a bare `actions/setup-python` with no pip install.
  * DETERMINISTIC + IDEMPOTENT — stable UUIDv5 IDs from a fixed namespace, a fixed
    EPOCH for timestamps (never now()), inputs fully determine outputs. Running it
    twice on unchanged README.MD produces byte-identical files (no spurious diffs).

Never hand-edit the three generated files; edit README.MD and let CI rebuild them.

Usage:
  python tools/build_exports.py                # build from ./README.MD into repo root
  python tools/build_exports.py --check         # build to temp, exit 1 if outputs would change
"""
from __future__ import annotations
import argparse, html, json, re, sys, uuid
from pathlib import Path

# ---- determinism anchors -----------------------------------------------------
# Fixed namespace + epoch so IDs and timestamps depend only on content, never on
# wall-clock time. Do not change these once the repo is public (IDs would churn).
NS = uuid.UUID("7f1c9e2a-0b64-5d3f-9a21-6e4c8b0a1d55")     # project-local UUIDv5 namespace
EPOCH = "2024-01-01T00:00:00.000Z"                          # STIX created/modified stamp

MAIN_HEADER_STARTS = "| Technique"
MULTI_SEP = re.compile(r"\s*;\s*")        # separator for encoding/propagation/models/atlas
BLANKS = {"", "-", "—", "n/a", "none stated", "not stated"}
ATLAS_RE = re.compile(r"\bAML\.T\d{4}(?:\.\d{3})?\b")
URL_RE = re.compile(r"https?://[^\s)<>\]]+")
MD_LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")

# Map reporting-source domains to organization display names for STIX identity SDOs.
# Extend as new sources appear; an unmapped domain falls back to the bare host.
DOMAIN_ORG = {
    "anthropic.com": "Anthropic",
    "openai.com": "OpenAI",
    "microsoft.com": "Microsoft",
    "cloud.google.com": "Google",
    "blog.google": "Google",
    "deepmind.google": "Google DeepMind",
    "embracethered.com": "Embrace The Red",
    "simonwillison.net": "Simon Willison",
    "hiddenlayer.com": "HiddenLayer",
    "lakera.ai": "Lakera",
    "robustintelligence.com": "Robust Intelligence",
    "trailofbits.com": "Trail of Bits",
    "blog.trailofbits.com": "Trail of Bits",
    "portswigger.net": "PortSwigger",
    "owasp.org": "OWASP",
    "genai.owasp.org": "OWASP GenAI Security Project",
    "nvidia.com": "NVIDIA",
    "developer.nvidia.com": "NVIDIA",
    "arxiv.org": "arXiv",
    "ncsc.gov.uk": "NCSC UK",
    "cisa.gov": "CISA",
    "wired.com": "WIRED",
    "theregister.com": "The Register",
    "bleepingcomputer.com": "BleepingComputer",
    "thehackernews.com": "The Hacker News",
    "arstechnica.com": "Ars Technica",
    "schneier.com": "Bruce Schneier",
}


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def _split_row(line: str) -> list[str]:
    """Split a Markdown table row into unescaped cell strings."""
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    # split on unescaped pipes, then restore escaped pipes
    cells, buf, esc = [], [], False
    for ch in s:
        if esc:
            buf.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
            buf.append(ch)
        elif ch == "|":
            cells.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    cells.append("".join(buf))
    return [c.strip().replace("\\|", "|") for c in cells]


def _is_divider(cells: list[str]) -> bool:
    return all(re.fullmatch(r":?-{2,}:?", c.strip() or "-") for c in cells) and any("-" in c for c in cells)


def _clean(v: str) -> str:
    return "" if v.strip().lower() in BLANKS else v.strip()


def _multi(v: str) -> list[str]:
    v = _clean(v)
    return [p for p in (x.strip() for x in MULTI_SEP.split(v)) if p] if v else []


def _links(v: str) -> list[str]:
    v = _clean(v)
    if not v:
        return []
    out = []
    for m in MD_LINK_RE.finditer(v):
        out.append(m.group(2))
    if not out:
        out = URL_RE.findall(v.replace("<br>", " "))
    # de-dup, preserve order, cap at 4
    seen, res = set(), []
    for u in out:
        u = u.rstrip(".,);")
        if u not in seen:
            seen.add(u)
            res.append(u)
    return res[:4]


COLUMNS = ["technique", "delivery", "encoding", "propagation", "confirmed_models",
           "attack_source", "evidence", "vetting", "brief", "atlas", "reported", "link"]


def parse_main_table(md: str) -> list[dict]:
    lines = md.splitlines()
    rows, in_table = [], False
    for line in lines:
        stripped = line.strip()
        if not in_table:
            if stripped.startswith(MAIN_HEADER_STARTS) and stripped.count("|") >= 10:
                in_table = True
            continue
        if not stripped.startswith("|"):
            break  # table ended
        cells = _split_row(line)
        if _is_divider(cells):
            continue
        # pad/truncate to 11 columns
        cells = (cells + [""] * len(COLUMNS))[:len(COLUMNS)]
        raw = dict(zip(COLUMNS, cells))
        entry = {
            "technique": _clean(raw["technique"]),
            "delivery": _multi(raw["delivery"]),
            "encoding": _multi(raw["encoding"]),
            "propagation": _multi(raw["propagation"]),
            "confirmed_models": _multi(raw["confirmed_models"]),
            "attack_source": _clean(raw["attack_source"]),
            "evidence": _clean(raw["evidence"]) or "Unclear",
            "vetting": _clean(raw["vetting"]) or "Not fully vetted",
            "brief": _clean(raw["brief"]),
            "atlas": ATLAS_RE.findall(raw["atlas"]),
            "reported": _clean(raw["reported"]),
            "links": _links(raw["link"]),
        }
        if entry["technique"]:
            rows.append(entry)
    return rows


APPENDIX_RE = re.compile(r"^#{2,3}\s+Appendix\s+([ABC])\b.*$", re.I)


def parse_appendices(md: str) -> dict:
    """Extract the controlled vocabulary bullet lists under Appendix A/B/C."""
    vocab = {"A": [], "B": [], "C": []}
    cur = None
    for line in md.splitlines():
        m = APPENDIX_RE.match(line.strip())
        if m:
            cur = m.group(1).upper()
            continue
        if cur and line.strip().startswith("#"):
            cur = None
            continue
        if cur:
            bm = re.match(r"^\s*[-*]\s+\*{0,2}([^*|:]+)", line)
            if bm:
                term = bm.group(1).strip().rstrip(".")
                if term:
                    vocab[cur].append(term)
    return vocab


# ---------------------------------------------------------------------------
# Date parsing (for stable sort keys) — content-derived, never now()
# ---------------------------------------------------------------------------
MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}


def sort_key(reported: str):
    """Return (year, month) for 'Mon YYYY'; blanks/Unknown sort last."""
    if not reported:
        return (0, 0)
    m = re.search(r"([A-Za-z]{3,})\.?\s+(\d{4})", reported)
    if m and m.group(1)[:3].lower() in MONTHS:
        return (int(m.group(2)), MONTHS[m.group(1)[:3].lower()])
    y = re.search(r"(\d{4})", reported)
    return (int(y.group(1)), 0) if y else (0, 0)


# ---------------------------------------------------------------------------
# Emitters
# ---------------------------------------------------------------------------
def build_tracker_json(entries, vocab):
    out = []
    for e in entries:
        yr, mo = sort_key(e["reported"])
        d = dict(e)
        d["sort_year"] = yr
        d["sort_month"] = mo
        d["not_fully_vetted"] = e["vetting"].strip().lower().startswith("not")
        out.append(d)
    facets = {
        "delivery": sorted({v for e in entries for v in e["delivery"]}),
        "encoding": sorted({v for e in entries for v in e["encoding"]}),
        "propagation": sorted({v for e in entries for v in e["propagation"]}),
        "confirmed_models": sorted({v for e in entries for v in e["confirmed_models"]}),
        "evidence": sorted({e["evidence"] for e in entries}),
        "vetting": sorted({e["vetting"] for e in entries}),
    }
    return {
        "generated_from": "README.MD",
        "schema_version": 1,
        "count": len(out),
        "vocabulary": {"delivery": vocab["A"], "encoding": vocab["B"], "propagation": vocab["C"]},
        "facets": facets,
        "entries": out,
    }


def _host(url: str) -> str:
    m = re.match(r"https?://([^/]+)", url)
    return (m.group(1).lower().lstrip("www.") if m else "").lstrip("www.")


def _org_for(url: str) -> str:
    h = _host(url)
    for dom, name in DOMAIN_ORG.items():
        if dom in h:
            return name
    return h or "Unknown source"


def _id(kind: str, seed: str) -> str:
    return f"{kind}--{uuid.uuid5(NS, kind + '|' + seed)}"


def build_stix(entries):
    objs, seen_ids = [], set()

    def add(o):
        if o["id"] not in seen_ids:
            seen_ids.add(o["id"])
            objs.append(o)

    for e in entries:
        ap_id = _id("attack-pattern", e["technique"])
        ext_refs = [{"source_name": "mitre-atlas", "external_id": a,
                     "url": f"https://atlas.mitre.org/techniques/{a}"} for a in e["atlas"]]
        for u in e["links"]:
            ext_refs.append({"source_name": _org_for(u), "url": u})
        ap = {
            "type": "attack-pattern", "spec_version": "2.1", "id": ap_id,
            "created": EPOCH, "modified": EPOCH,
            "name": e["technique"],
            "description": e["brief"] or e["technique"],
            "external_references": ext_refs,
            "x_pi_vetting": e["vetting"],
            "x_pi_evidence_class": e["evidence"],
            "confidence": 15 if e["vetting"].lower().startswith("not") else 85,
        }
        if e["delivery"]:
            ap["x_pi_delivery_method"] = e["delivery"]
        if e["encoding"]:
            ap["x_pi_encoding"] = e["encoding"]
        if e["propagation"]:
            ap["x_pi_propagation"] = e["propagation"]
        if e["confirmed_models"]:
            ap["x_pi_confirmed_models"] = e["confirmed_models"]
        add(ap)

        # named attack source -> identity + relationship
        src = e["attack_source"]
        if src:
            actor_id = _id("identity", src)
            add({"type": "identity", "spec_version": "2.1", "id": actor_id,
                 "created": EPOCH, "modified": EPOCH, "name": src,
                 "identity_class": "individual" if src.lower().startswith("researcher") else "unknown"})
            rel_id = _id("relationship", "uses|" + src + "|" + e["technique"])
            add({"type": "relationship", "spec_version": "2.1", "id": rel_id,
                 "created": EPOCH, "modified": EPOCH,
                 "relationship_type": "uses", "source_ref": actor_id, "target_ref": ap_id})

        # reporting sources -> identity(org) + report
        for u in e["links"]:
            org = _org_for(u)
            org_id = _id("identity", "org|" + org)
            add({"type": "identity", "spec_version": "2.1", "id": org_id,
                 "created": EPOCH, "modified": EPOCH, "name": org, "identity_class": "organization"})
            rep_id = _id("report", u)
            add({"type": "report", "spec_version": "2.1", "id": rep_id,
                 "created": EPOCH, "modified": EPOCH,
                 "name": f"{org}: {e['technique']}", "report_types": ["attack-pattern"],
                 "published": EPOCH, "created_by_ref": org_id,
                 "object_refs": [ap_id], "external_references": [{"source_name": org, "url": u}]})

    objs.sort(key=lambda o: (o["type"], o["id"]))
    return {"type": "bundle", "id": _id("bundle", "prompt-injection-in-the-wild"), "objects": objs}


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
HTML_TEMPLATE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Prompt Injection in the Wild</title>
<style>
:root{--bg:#0b0e14;--panel:#121722;--panel2:#0f141d;--line:#20293a;--fg:#e6edf6;--mut:#8ea0b8;
--accent:#00e5ff;--warn:#ffb020;--warnbg:#2a2010;--chip:#182234;--link:#5cc8ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
header{padding:22px 24px 8px}
h1{margin:0 0 4px;font-size:22px;letter-spacing:.3px}
h1 .p{color:var(--accent)}
.sub{color:var(--mut);font-size:13px;max-width:920px}
.controls{position:sticky;top:0;z-index:5;background:linear-gradient(var(--bg),var(--bg) 70%,transparent);padding:14px 24px;display:flex;flex-wrap:wrap;gap:10px;align-items:center;border-bottom:1px solid var(--line)}
input[type=search]{flex:1;min-width:220px;background:var(--panel);border:1px solid var(--line);color:var(--fg);padding:9px 12px;border-radius:8px;font-size:14px}
select,button{background:var(--panel);border:1px solid var(--line);color:var(--fg);padding:8px 10px;border-radius:8px;font-size:13px;cursor:pointer}
.count{color:var(--mut);font-size:13px;margin-left:auto}
.cols{padding:8px 24px;display:none;flex-wrap:wrap;gap:6px 14px;border-bottom:1px solid var(--line);background:var(--panel2)}
.cols.open{display:flex}
.cols label{color:var(--mut);font-size:12px;user-select:none}
.wrap{overflow-x:auto;padding:0 12px 60px}
table{border-collapse:collapse;width:100%;min-width:1100px}
th,td{text-align:left;vertical-align:top;padding:9px 10px;border-bottom:1px solid var(--line)}
th{position:sticky;top:0;background:var(--panel);color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px;cursor:pointer;white-space:nowrap}
th:hover{color:var(--fg)}
th .ar{opacity:.5;font-size:10px}
td.tech{font-weight:600;min-width:160px}
.chip{display:inline-block;background:var(--chip);border:1px solid var(--line);border-radius:999px;padding:1px 8px;margin:1px 3px 1px 0;font-size:12px;white-space:nowrap}
.pill{display:inline-block;border-radius:999px;padding:1px 8px;font-size:11px;font-weight:600;white-space:nowrap}
.pill.nv{background:var(--warnbg);color:var(--warn);border:1px solid #4a3410}
.pill.ok{background:#10241a;color:#3ad07a;border:1px solid #16402a}
.pill.wild{background:#2a1410;color:#ff7a59;border:1px solid #4a1e12}
.pill.research{background:#101d2a;color:#5cc8ff;border:1px solid #16324a}
.pill.vendor{background:#191026;color:#c08cff;border:1px solid #34204a}
.pill.unclear{background:#1a1d24;color:#8ea0b8;border:1px solid #2a3140}
.mut{color:var(--mut)}
.brief{max-width:420px}
.brief.clip{max-height:3.1em;overflow:hidden}
.more{color:var(--accent);cursor:pointer;font-size:12px;display:inline-block;margin-top:2px}
.src a{display:inline-block;margin:0 6px 2px 0}
footer{color:var(--mut);font-size:12px;padding:18px 24px;border-top:1px solid var(--line)}
.em{color:var(--mut)}
@media(max-width:640px){.sub{font-size:12px}}
</style></head><body>
<header>
<h1><span class="p">Prompt Injection</span> in the Wild</h1>
<div class="sub">A tracker of publicly reported prompt-injection techniques, broken down by <b>delivery method</b>, <b>encoding</b>, and <b>propagation behavior</b>, with the models each was confirmed against, the reporting source, and (where known) the attack source. Fields are left blank when a report does not state them; techniques whose details are vague or unconfirmed are marked <b>Not fully vetted</b>. Nothing here is guessed.</div>
</header>
<div class="controls">
<input id="q" type="search" placeholder="Search techniques, models, sources, briefs…">
<select id="fDelivery"></select>
<select id="fEncoding"></select>
<select id="fProp"></select>
<select id="fEvidence"><option value="">All evidence</option><option>In-the-wild</option><option>Research / red-team</option><option>Vendor advisory</option><option>Unclear</option></select>
<select id="fVet"><option value="">All vetting</option><option>Confirmed</option><option>Not fully vetted</option></select>
<button id="colsBtn">Columns ▾</button>
<span class="count" id="count"></span>
</div>
<div class="cols" id="cols"></div>
<div class="wrap"><table id="t"><thead></thead><tbody></tbody></table></div>
<footer id="foot"></footer>
<script>
const DATA = __DATA__;
const VOCAB = __VOCAB__;
const GENSTAMP = "__STAMP__";
const COLS = [
 {k:"technique",label:"Technique",on:1},
 {k:"delivery",label:"Delivery",on:1,arr:1},
 {k:"encoding",label:"Encoding",on:1,arr:1},
 {k:"propagation",label:"Propagation",on:1,arr:1},
 {k:"confirmed_models",label:"Confirmed Models",on:1,arr:1},
 {k:"attack_source",label:"Attack Source",on:1},
 {k:"evidence",label:"Evidence",on:1},
 {k:"vetting",label:"Vetting",on:1},
 {k:"brief",label:"Brief",on:1},
 {k:"atlas",label:"ATLAS",on:0,arr:1},
 {k:"reported",label:"Reported",on:1},
 {k:"links",label:"Sources",on:1},
];
let sortK="reported", sortDir=-1;
const $=s=>document.querySelector(s);
const esc=s=>(s==null?"":String(s)).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const EM='<span class="em">—</span>';

function fillFacet(sel,label,vals){
 sel.innerHTML='<option value="">'+label+'</option>'+vals.map(v=>'<option>'+esc(v)+'</option>').join('');
}
fillFacet($("#fDelivery"),"All delivery",VOCAB.delivery.length?VOCAB.delivery:uniq("delivery"));
fillFacet($("#fEncoding"),"All encoding",VOCAB.encoding.length?VOCAB.encoding:uniq("encoding"));
fillFacet($("#fProp"),"All propagation",VOCAB.propagation.length?VOCAB.propagation:uniq("propagation"));
function uniq(k){const s=new Set();DATA.forEach(e=>(e[k]||[]).forEach(v=>s.add(v)));return [...s].sort();}

// column toggles
$("#cols").innerHTML=COLS.map((c,i)=>'<label><input type="checkbox" data-i="'+i+'" '+(c.on?"checked":"")+'> '+esc(c.label)+'</label>').join('');
$("#colsBtn").onclick=()=>$("#cols").classList.toggle("open");
$("#cols").addEventListener("change",e=>{COLS[e.target.dataset.i].on=e.target.checked;render();});

function cell(c,e){
 const v=e[c.k];
 if(c.k==="links"){const a=(v||[]);return a.length?'<span class="src">'+a.map((u,i)=>'<a href="'+esc(u)+'" target="_blank" rel="noopener">['+(i+1)+']</a>').join('')+'</span>':EM;}
 if(c.k==="evidence"){const m={"In-the-wild":"wild","Research / red-team":"research","Vendor advisory":"vendor"};return v?'<span class="pill '+(m[v]||"unclear")+'">'+esc(v)+'</span>':EM;}
 if(c.k==="vetting"){const nv=/^not/i.test(v);return '<span class="pill '+(nv?"nv":"ok")+'">'+esc(nv?"Not fully vetted":"Confirmed")+'</span>';}
 if(c.k==="brief"){if(!v)return EM;const id="b"+e._i;return '<div class="brief clip" id="'+id+'">'+linkify(v)+'</div><span class="more" data-b="'+id+'">more ▾</span>';}
 if(c.arr){const a=(v||[]);return a.length?a.map(x=>'<span class="chip">'+esc(x)+'</span>').join(''):EM;}
 return v?esc(v):EM;
}
function linkify(s){return esc(s).replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g,'<a href="$2" target="_blank" rel="noopener">$1</a>').replace(/(^|[^"(>])(https?:\/\/[^\s<]+)/g,'$1<a href="$2" target="_blank" rel="noopener">$2</a>');}

function render(){
 const q=$("#q").value.trim().toLowerCase();
 const fd=$("#fDelivery").value,fe=$("#fEncoding").value,fp=$("#fProp").value,fev=$("#fEvidence").value,fv=$("#fVet").value;
 const show=COLS.filter(c=>c.on);
 $("#t").querySelector("thead").innerHTML="<tr>"+show.map(c=>'<th data-k="'+c.k+'">'+esc(c.label)+' <span class="ar">'+(sortK===c.k?(sortDir<0?"▼":"▲"):"")+'</span></th>').join('')+"</tr>";
 let rows=DATA.map((e,i)=>({...e,_i:i}));
 rows=rows.filter(e=>{
   if(fd&&!(e.delivery||[]).includes(fd))return false;
   if(fe&&!(e.encoding||[]).includes(fe))return false;
   if(fp&&!(e.propagation||[]).includes(fp))return false;
   if(fev&&e.evidence!==fev)return false;
   if(fv&&e.vetting!==fv)return false;
   if(q){const hay=JSON.stringify(e).toLowerCase();if(!hay.includes(q))return false;}
   return true;
 });
 rows.sort((a,b)=>{
   if(sortK==="reported"){const d=(a.sort_year-b.sort_year)||(a.sort_month-b.sort_month);
     if((a.sort_year||0)===0&&(b.sort_year||0)!==0)return 1;
     if((b.sort_year||0)===0&&(a.sort_year||0)!==0)return -1;
     return d*sortDir;}
   const av=(Array.isArray(a[sortK])?a[sortK].join(", "):(a[sortK]||"")).toLowerCase();
   const bv=(Array.isArray(b[sortK])?b[sortK].join(", "):(b[sortK]||"")).toLowerCase();
   return av<bv?-sortDir:av>bv?sortDir:0;
 });
 $("#t").querySelector("tbody").innerHTML=rows.map(e=>"<tr>"+show.map(c=>'<td class="'+(c.k==="technique"?"tech":"")+'">'+cell(c,e)+"</td>").join('')+"</tr>").join('');
 $("#count").textContent=rows.length+" / "+DATA.length+" techniques";
 document.querySelectorAll("th").forEach(th=>th.onclick=()=>{const k=th.dataset.k;if(sortK===k)sortDir*=-1;else{sortK=k;sortDir=1;}render();});
 document.querySelectorAll(".more").forEach(m=>m.onclick=()=>{const el=document.getElementById(m.dataset.b);el.classList.toggle("clip");m.textContent=el.classList.contains("clip")?"more ▾":"less ▲";});
}
["#q","#fDelivery","#fEncoding","#fProp","#fEvidence","#fVet"].forEach(s=>$(s).addEventListener("input",render));
$("#foot").innerHTML=DATA.length+" techniques · generated from README.MD · auto-updated on each commit · "+esc(GENSTAMP);
render();
</script>
</body></html>
"""


def build_html(tracker):
    data = json.dumps(tracker["entries"], ensure_ascii=False, separators=(",", ":"))
    vocab = json.dumps(tracker["vocabulary"], ensure_ascii=False, separators=(",", ":"))
    nv = sum(1 for e in tracker["entries"] if e.get("not_fully_vetted"))
    stamp = f"{tracker['count'] - nv} confirmed · {nv} not fully vetted"
    return (HTML_TEMPLATE
            .replace("__DATA__", data)
            .replace("__VOCAB__", vocab)
            .replace("__STAMP__", stamp))


# ---------------------------------------------------------------------------
def build_all(readme: str):
    entries = parse_main_table(readme)
    vocab = parse_appendices(readme)
    tracker = build_tracker_json(entries, vocab)
    stix = build_stix(entries)
    html_out = build_html(tracker)
    return {
        "tracker.json": json.dumps(tracker, ensure_ascii=False, indent=2) + "\n",
        "stix/prompt-injection-stix2.1.json": json.dumps(stix, ensure_ascii=False, indent=2) + "\n",
        "index.html": html_out,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".", help="repo root (contains README.MD)")
    ap.add_argument("--check", action="store_true", help="exit 1 if any generated file would change")
    a = ap.parse_args()
    root = Path(a.root)
    readme = (root / "README.MD").read_text(encoding="utf-8")
    outputs = build_all(readme)
    changed = []
    for rel, content in outputs.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        old = p.read_text(encoding="utf-8") if p.exists() else None
        if old != content:
            changed.append(rel)
            if not a.check:
                p.write_text(content, encoding="utf-8")
    n = json.loads(outputs["tracker.json"])["count"]
    if a.check:
        if changed:
            print("would change:", ", ".join(changed))
            sys.exit(1)
        print(f"up to date · {n} techniques")
    else:
        print(f"wrote {len(outputs)} files · {n} techniques" +
              (f" · updated: {', '.join(changed)}" if changed else " · no changes"))


if __name__ == "__main__":
    main()
