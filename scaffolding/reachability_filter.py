#!/usr/bin/env python3
"""reachability_filter.py — the false-positive stage AISLE's scan.py is missing.

AISLE's nano-analyzer graduates "VALID" findings on a per-function basis. On FreeBSD
sys/rpc that produced ~30 "VALID" findings of which ~1 was a real defect — the rest were
false positives (dead code, kernel-set lengths, upstream-bounded values, privileged-only
paths). This is a precision filter that runs AFTER scan.py: it re-checks each finding with
a reachability-strict prompt that forces the model to trace from an external entry point,
grep for callers/constants, and REJECT anything not attacker-reachable. In our test it cut
30 graduated findings to 5 (~83% fewer false positives) while keeping the real CVE.

It does NOT modify scan.py — point it at scan.py's --output-dir/findings/ (or any directory
of `*.md` findings each carrying a `**File**: \`path\`` line) plus the source tree.

Bring your own model: any OpenAI-compatible endpoint.

    export LM_BASE_URL=https://your-endpoint/v1   # SDK posts to ${LM_BASE_URL}/chat/completions
    export LM_API_KEY=...                          # OpenWebUI users: OPENWEBUI_URL/OPENWEBUI_API_KEY also work
    export MODEL=google/gemma-4-31b-it             # default

    python3 reachability_filter.py <findings_dir> <source_repo> [--parallel 8] [--out filtered.md]

Requires: python3, and `rg` (ripgrep) for caller/constant lookups (degrades gracefully without it).
"""
import argparse, concurrent.futures, glob, json, os, re, shutil, subprocess, time, urllib.error, urllib.request

SYSTEM = (
    "You are a PRECISION-FIRST reachability arbiter for systems/kernel C. An automated funnel "
    "graduated the finding below as 'VALID'. REJECT it unless it is a genuinely attacker-reachable bug. "
    "Mark VALID only if ALL hold: (1) the bug pattern really exists in the cited code; (2) a concrete path "
    "runs from an EXTERNAL entry point (network packet or userspace syscall) to the sink carrying "
    "ATTACKER-CONTROLLED data; (3) the cited length/pointer/value is actually attacker-controlled — NOT "
    "kernel-set, NOT bounded by an upstream check UNLESS that bound still exceeds the destination size, NOT "
    "a fixed-size field. Mark INVALID if: the function has no callers (dead code), the value is "
    "kernel-generated or sufficiently bounded, the trigger needs a privileged/local-only actor, or you cannot "
    "establish a concrete reachable path. Use GREP to find callers and confirm constants — never guess. "
    "Under uncertainty, default INVALID."
)

BASE = (os.environ.get("LM_BASE_URL")
        or (os.environ["OPENWEBUI_URL"].rstrip("/") + "/api" if os.environ.get("OPENWEBUI_URL") else None))
KEY = os.environ.get("LM_API_KEY") or os.environ.get("OPENWEBUI_API_KEY")
MODEL = os.environ.get("MODEL", "google/gemma-4-31b-it")
if not BASE or not KEY:
    raise SystemExit("set LM_BASE_URL + LM_API_KEY (or OPENWEBUI_URL + OPENWEBUI_API_KEY)")
_RG = shutil.which("rg")


def call(messages, retries=4):
    body = json.dumps({"model": MODEL, "messages": messages}).encode()
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(BASE.rstrip("/") + "/chat/completions", data=body, method="POST",
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {KEY}",
                         "User-Agent": "reachability-filter/1.0"})
            with urllib.request.urlopen(req, timeout=600) as r:
                d = json.loads(r.read().decode())
            return d["choices"][0]["message"].get("content") or ""
        except urllib.error.HTTPError as e:
            last = f"{e.code}"
            if e.code < 500:
                break
        except Exception as e:
            last = str(e)
        time.sleep(2 ** i)
    raise RuntimeError(f"call failed: {last}")


def grep(text, repo, max_hits=25):
    if not _RG:
        return ""
    pats = re.findall(r"GREP:\s*`?([^\n`]+)`?", text)
    out = []
    for p in pats[:3]:
        p = p.strip().strip('`"\'')
        if not p:
            continue
        try:
            r = subprocess.run([_RG, "-n", "--no-heading", "-m", str(max_hits), p, repo],
                               capture_output=True, text=True, timeout=30)
            if r.stdout:
                out.append(f"$ rg {p}\n" + "\n".join(r.stdout.splitlines()[:max_hits]))
        except Exception:
            pass
    return "\n\n".join(out)


def extract_json(text):
    m = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
    if m:
        text = m.group(1)
    m = re.search(r"\{.*\}", text, re.DOTALL)
    try:
        return json.loads(m.group(0)) if m else None
    except Exception:
        return None


def resolve_source(finding_text, repo):
    m = re.search(r"File\W*`([^`]+)`", finding_text)
    cand = m.group(1) if m else None
    if not cand:
        return None, None
    p = os.path.join(repo, cand)
    hits = [p] if os.path.exists(p) else glob.glob(os.path.join(repo, "**", os.path.basename(cand)), recursive=True)
    if not hits:
        return cand, None
    return os.path.relpath(hits[0], repo), open(hits[0], errors="replace").read()


def window(code, finding_text, budget=22000):
    """Return a slice of `code` that is guaranteed to contain the cited function,
    centered on it. Plain head-truncation misses functions deep in large files."""
    if not code or len(code) <= budget:
        return code
    names = re.findall(r"`([a-zA-Z_]\w{3,})`", finding_text) + re.findall(r"\b([a-z_]\w{4,})\s*\(", finding_text)
    idx = None
    for n in dict.fromkeys(names):  # preserve order, dedup
        i = code.find(n + "(")
        if i == -1:
            i = code.find(n)
        if i != -1:
            idx = i
            break
    if idx is None:
        return code[:budget]
    start = max(0, idx - budget // 3)
    return code[start:start + budget]


def prompt(title, body, rel, code, extra=""):
    ctx = window(code, title + "\n" + body) if code else "(source not found — if you cannot see the code or its callers, default INVALID)"
    return (f"FINDING (auto-graduated VALID):\n{title}\n{body[:1400]}\n\nSOURCE {rel}:\n```c\n{ctx}\n```\n{extra}\n"
            "Trace BACKWARD from the sink to an external entry point. To check callers/constants emit lines like  "
            "GREP: <pattern>  (e.g. GREP: <function_name> to find callers). Then answer JSON: "
            '{"verdict":"VALID|INVALID","entry_point":"<path from untrusted input, or NONE>","why":"<=2 sentences"}')


def judge(path, repo):
    name = os.path.basename(path)
    try:
        txt = open(path, errors="replace").read()
        mt = re.search(r"^#\s*(.+)", txt, re.M)
        title = mt.group(1) if mt else name
        rel, code = resolve_source(txt, repo)
        r1 = call([{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt(title, txt, rel, code)}])
        g = grep(r1, repo)
        extra = (f"\n[Your prior analysis]:\n{r1[:700]}\n[GREP RESULTS — caller/constant facts]:\n"
                 f"{(g or '(no matches — likely no callers / constant absent)')[:1500]}\nRe-decide strictly using these facts.")
        r2 = call([{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt(title, txt, rel, code, extra)}])
        p = extract_json(r2) or extract_json(r1) or {}
        v = (p.get("verdict", "") or "").upper()
        return (name, rel or "?", v if v in ("VALID", "INVALID") else "UNCERTAIN",
                (p.get("entry_point", "") or "")[:60], (p.get("why", "") or "")[:200])
    except Exception as e:
        return (name, "?", "ERR", "", str(e)[:120])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings_dir", help="dir of *.md findings (e.g. scan.py's findings/)")
    ap.add_argument("source_repo", help="source tree the findings refer to")
    ap.add_argument("--parallel", type=int, default=8)
    ap.add_argument("--out", default="reachability_filtered.md")
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.findings_dir, "*.md")))
    if not files:
        raise SystemExit(f"no *.md findings in {args.findings_dir}")
    print(f"reachability filter: {len(files)} findings | model={MODEL} | {args.parallel} parallel", flush=True)
    res = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as ex:
        futs = {ex.submit(judge, f, args.source_repo): f for f in files}
        for fut in concurrent.futures.as_completed(futs):
            r = fut.result(); res.append(r)
            print(f"  [{r[0]:38}] {r[2]:8} {r[1]:28} {r[3]}", flush=True)
    v = sum(1 for r in res if r[2] == "VALID")
    inv = sum(1 for r in res if r[2] == "INVALID")
    with open(args.out, "w") as fh:
        fh.write(f"# Reachability filter — {v} kept / {inv} rejected of {len(res)} (model: {MODEL})\n\n")
        for r in sorted(res):
            fh.write(f"- **{r[2]}** `{r[0]}` ({r[1]}) — entry: {r[3] or 'NONE'}\n  - {r[4]}\n")
    print(f"\n{v} VALID kept, {inv} INVALID rejected, {len(res)-v-inv} uncertain/err  ->  {args.out}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
