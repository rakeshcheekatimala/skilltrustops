# ruff: noqa: E501
"""Generate a dependency-free offline HTML dashboard from raw benchmark data."""

from __future__ import annotations

import argparse
import gzip
import json
import statistics
from pathlib import Path


def load(path: Path) -> dict[str, object]:
    with gzip.open(path, "rt", encoding="utf-8") as file:
        return json.load(file)


def median(values: list[float]) -> float:
    return round(statistics.median(values), 3)


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    return round(ordered[round((len(ordered) - 1) * quantile)], 3)


def dashboard_data(results: Path) -> dict[str, object]:
    profiles = [load(path) for path in sorted(results.glob("*.json.gz"))]
    if not profiles:
        raise SystemExit(f"No .json.gz benchmark results found in {results}")
    chosen = next(
        (item for item in profiles if item["profile"] == "cpu-100-mem-512m"),
        profiles[0],
    )
    runs = chosen["runs"]
    by_path: dict[str, list[dict[str, object]]] = {}
    for run in runs:
        for skill in run["report"]["skills"]:
            by_path.setdefault(skill["relative_path"], []).append(skill)

    skills = []
    for path, observations in sorted(by_path.items()):
        first = observations[0]
        source_parts = path.split("/")
        source = "/".join(source_parts[:2])
        check_times: dict[str, list[float]] = {
            "lint": [],
            "security": [],
            "privacy": [],
        }
        rules: set[str] = set()
        finding_count = 0
        for observation in observations:
            for check in observation["checks"]:
                check_times[check["command"]].append(check["duration_ms"])
                if observation is first:
                    finding_count += check["finding_count"]
                    rules.update(finding["rule_id"] for finding in check["findings"])
        durations = [observation["duration_ms"] for observation in observations]
        skills.append(
            {
                "name": first["skill"],
                "source": source,
                "path": path,
                "status": first["status"],
                "median_ms": median(durations),
                "p95_ms": percentile(durations, 0.95),
                "lint_ms": median(check_times["lint"]),
                "security_ms": median(check_times["security"]),
                "privacy_ms": median(check_times["privacy"]),
                "findings": finding_count,
                "rules": sorted(rules),
            }
        )

    profile_rows = []
    for profile in profiles:
        runtime = profile["runtime"]
        summary = profile["summary"]
        profile_rows.append(
            {
                "profile": profile["profile"],
                "cpu": runtime["cgroup_cpu_max"],
                "memory_bytes": int(runtime["cgroup_memory_max"]),
                "median_ms": summary["median_wall_duration_ms"],
                "throughput": summary["median_throughput_skills_per_second"],
                "p95_ms": summary["skill_latency_ms"]["p95"],
                "peak_memory_bytes": int(runtime["cgroup_memory_peak"]),
            }
        )
    return {
        "generated_from": chosen["profile"],
        "corpus": chosen["corpus"],
        "policy": runs[0]["report"]["policy"],
        "summary": chosen["summary"],
        "outcomes": runs[-1]["report"]["summary"],
        "skills": skills,
        "profiles": profile_rows,
    }


def render(data: dict[str, object]) -> str:
    encoded = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    return TEMPLATE.replace("__BENCHMARK_DATA__", encoded)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(render(dashboard_data(args.results)), encoding="utf-8")
    print(f"WROTE {args.output}")


TEMPLATE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SkillTrustOps reproducible benchmark</title>
<style>
:root{color-scheme:light dark;--bg:#f4f7f6;--panel:#fff;--text:#16201d;--muted:#5b6b66;--line:#d9e2df;--accent:#087f5b;--accent2:#e9f6f1;--warn:#a35b00;--warnbg:#fff4df;--bad:#b42318;--shadow:0 8px 30px #10231c12} @media(prefers-color-scheme:dark){:root{--bg:#0d1412;--panel:#141e1b;--text:#edf7f3;--muted:#9bb0a9;--line:#293a35;--accent:#56d6a8;--accent2:#17372d;--warn:#ffc66d;--warnbg:#3a2d14;--bad:#ff8a80;--shadow:none}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:1440px;margin:auto;padding:28px}h1{font-size:clamp(28px,4vw,48px);letter-spacing:-.035em;margin:0 0 6px}h2{margin:32px 0 12px;font-size:22px}h3{margin:0 0 8px}.sub,.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:22px 0}.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;box-shadow:var(--shadow)}.metric{font-size:28px;font-weight:700;letter-spacing:-.03em}.metric-label{color:var(--muted)}.notice{background:var(--warnbg);border-left:4px solid var(--warn);padding:12px 15px;border-radius:8px}.controls{display:grid;grid-template-columns:minmax(220px,2fr) 1fr 1fr;gap:10px;margin:12px 0}.controls input,.controls select{width:100%;padding:10px 12px;border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:8px}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:12px;background:var(--panel)}table{border-collapse:collapse;width:100%;min-width:940px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);white-space:nowrap}th{position:sticky;top:0;background:var(--panel);font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);cursor:pointer}tr:hover td{background:var(--accent2)}.num{text-align:right;font-variant-numeric:tabular-nums}.pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700}.passed{background:var(--accent2);color:var(--accent)}.failed{background:var(--warnbg);color:var(--warn)}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}pre{overflow:auto;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}.bar-row{display:grid;grid-template-columns:180px 1fr 90px;gap:10px;align-items:center;margin:10px 0}.bar{height:12px;background:var(--line);border-radius:99px;overflow:hidden}.bar span{display:block;height:100%;background:var(--accent)}details{margin:10px 0}summary{cursor:pointer;font-weight:700}footer{margin:38px 0;color:var(--muted)}@media(max-width:850px){main{padding:18px}.grid{grid-template-columns:1fr 1fr}.controls,.two{grid-template-columns:1fr}.bar-row{grid-template-columns:120px 1fr 75px}}@media(max-width:480px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body><main>
<header><h1>SkillTrustOps benchmark</h1><div class="sub">Granular, offline, reproducible static analysis evidence · no LLM · no API key</div></header>
<section class="grid" id="metrics"></section>
<p class="notice"><strong>Interpretation:</strong> “Review required” means deterministic findings exist. It does not mean malicious, unsafe, or exploitable. These results measure operation and throughput; detector accuracy requires an adjudicated labeled dataset.</p>
<section><h2>Docker resource comparison</h2><div class="two"><div class="card" id="bars"></div><div class="table-wrap"><table id="profiles"><thead><tr><th>Profile</th><th class="num">Median</th><th class="num">Skills/s</th><th class="num">p95/skill</th><th class="num">Peak RAM</th></tr></thead><tbody></tbody></table></div></div></section>
<section><h2>Every skill: representative 1 CPU / 512 MiB profile</h2><div class="sub">Median and p95 across five runs. Click any column header to sort.</div><div class="controls"><input id="search" aria-label="Search skills" placeholder="Search name, source, path, or rule"><select id="source" aria-label="Filter source"><option value="">All sources</option></select><select id="status" aria-label="Filter status"><option value="">All outcomes</option><option value="passed">No findings</option><option value="failed">Review required</option></select></div><div class="muted" id="count"></div><div class="table-wrap"><table id="skills"><thead><tr><th data-key="name">Skill</th><th data-key="source">Source</th><th data-key="status">Outcome</th><th data-key="median_ms" class="num">Median ms</th><th data-key="p95_ms" class="num">p95 ms</th><th data-key="lint_ms" class="num">Lint</th><th data-key="security_ms" class="num">Security</th><th data-key="privacy_ms" class="num">Privacy</th><th data-key="findings" class="num">Findings</th><th data-key="rules">Rules</th></tr></thead><tbody></tbody></table></div></section>
<section><h2>What recommended-v2 tests</h2><div class="two"><div class="card"><h3>Lint and input safety</h3><ul><li>Recursive discovery of regular, non-symlink <code>SKILL.md</code> files</li><li>UTF-8 and 1 MiB file limit</li><li>YAML frontmatter parsing</li><li>Agent Skills name, directory match, description, allowed fields, metadata, compatibility, license and body rules</li></ul></div><div class="card"><h3>Security and privacy</h3><ul><li>Private-key, AWS, GitHub and generic credential patterns</li><li>Python <code>eval</code>/<code>exec</code>, <code>os.system</code>, and <code>subprocess(..., shell=True)</code></li><li>Recursive/forced <code>rm</code> and download piped to shell</li><li>Email, phone, US SSN and Luhn-valid payment-card patterns</li></ul></div></div><details><summary>Explicit non-coverage</summary><p>Static scanning reads each SKILL.md only. It does not execute it, call an LLM, require an API key, or currently analyze scripts, references, assets, dependencies, hooks, semantic prompt injection, obfuscation, or cross-file data flow. The deterministic reference red-team target tests harness behavior, not real-model safety.</p></details></section>
<section><h2>Reproduce on any Docker laptop</h2><pre>./benchmarks/market-scan/reproduce.sh</pre><ol><li>Builds the digest-pinned benchmark image.</li><li>Fetches eight repositories at immutable commits.</li><li>Verifies all 605 paths, sizes, and SHA-256 hashes.</li><li>Runs seven network-disabled CPU/RAM profiles, five runs each.</li><li>Checks raw artifact hashes and regenerates this dashboard.</li></ol><p class="muted">Expected run time depends on Docker allocation, CPU architecture, storage, thermal state, and concurrent workloads. Matching outcomes and corpus/policy hashes are required; timings should be compared as distributions, not exact identical numbers.</p></section>
<footer>Corpus and policy fingerprints are displayed above. Full compressed JSON retains every run, skill, check, finding and timing.</footer>
</main><script>
const DATA=__BENCHMARK_DATA__;const $=s=>document.querySelector(s);const fmt=n=>Number(n).toLocaleString(undefined,{maximumFractionDigits:3});const mib=n=>fmt(n/1048576)+" MiB";
const outcomes=DATA.outcomes;const metrics=[['Skills',DATA.corpus.skills],['Median total',fmt(DATA.summary.median_wall_duration_ms)+' ms'],['Throughput',fmt(DATA.summary.median_throughput_skills_per_second)+'/s'],['Scanner errors',outcomes.errors]];$('#metrics').innerHTML=metrics.map(x=>`<div class="card"><div class="metric">${x[1]}</div><div class="metric-label">${x[0]}</div></div>`).join('');
const max=Math.max(...DATA.profiles.map(x=>x.median_ms));$('#bars').innerHTML='<h3>Time for 605 skills</h3>'+DATA.profiles.map(x=>`<div class="bar-row"><span>${x.profile}</span><div class="bar"><span style="width:${x.median_ms/max*100}%"></span></div><span class="num">${fmt(x.median_ms)} ms</span></div>`).join('');$('#profiles tbody').innerHTML=DATA.profiles.map(x=>`<tr><td>${x.profile}</td><td class="num">${fmt(x.median_ms)} ms</td><td class="num">${fmt(x.throughput)}</td><td class="num">${fmt(x.p95_ms)} ms</td><td class="num">${mib(x.peak_memory_bytes)}</td></tr>`).join('');
const sources=[...new Set(DATA.skills.map(x=>x.source))].sort();$('#source').innerHTML+=[...sources].map(x=>`<option>${x}</option>`).join('');let sortKey='median_ms',ascending=true;const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function draw(){const q=$('#search').value.toLowerCase(),src=$('#source').value,status=$('#status').value;let rows=DATA.skills.filter(x=>(!src||x.source===src)&&(!status||x.status===status)&&(!q||[x.name,x.source,x.path,...x.rules].join(' ').toLowerCase().includes(q)));rows.sort((a,b)=>{const x=a[sortKey],y=b[sortKey];return (typeof x==='number'?x-y:String(x).localeCompare(String(y)))*(ascending?1:-1)});$('#count').textContent=`Showing ${rows.length} of ${DATA.skills.length} skills`;$('#skills tbody').innerHTML=rows.map(x=>`<tr title="${esc(x.path)}"><td>${esc(x.name)}</td><td>${esc(x.source)}</td><td><span class="pill ${x.status}">${x.status==='passed'?'No findings':'Review required'}</span></td><td class="num">${fmt(x.median_ms)}</td><td class="num">${fmt(x.p95_ms)}</td><td class="num">${fmt(x.lint_ms)}</td><td class="num">${fmt(x.security_ms)}</td><td class="num">${fmt(x.privacy_ms)}</td><td class="num">${x.findings}</td><td>${esc(x.rules.join(', '))}</td></tr>`).join('')}
['search','source','status'].forEach(id=>$('#'+id).addEventListener(id==='search'?'input':'change',draw));document.querySelectorAll('#skills th[data-key]').forEach(th=>th.addEventListener('click',()=>{if(sortKey===th.dataset.key)ascending=!ascending;else{sortKey=th.dataset.key;ascending=true}draw()}));draw();
</script></body></html>'''


if __name__ == "__main__":
    main()
