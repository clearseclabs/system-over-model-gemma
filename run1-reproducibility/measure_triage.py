"""Does the CVE finding survive AISLE's triage?

Takes the svc_rpc_gss_validate overflow finding from a HIT scan report (the
scan stage we showed catches it 17/17), fixes it, and runs AISLE's real
multi-round triage + arbiter on it via the OpenRouter (OpenWebUI) backend,
N times — isolating triage-stage variance from scan variance.
"""
import os, re, importlib.util, json

spec = importlib.util.spec_from_file_location("aisle_scan", "/tmp/aisle_scan.py")
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)

# --- backend: OpenWebUI proxy -> OpenRouter, with User-Agent (Cloudflare) ---
URL = os.environ["OPENWEBUI_URL"].rstrip("/") + "/api/chat/completions"
A.OPENROUTER_API_URL = URL
os.environ["OPENROUTER_API_KEY"] = os.environ["OPENWEBUI_API_KEY"]
_orig_resolve = A.resolve_backend
A.resolve_backend = lambda m, k: (lambda u, kk, n, h: (u, kk, n, {**h, "User-Agent": "OpenAI/Python 1.51.0"}))(*_orig_resolve(m, k))
# author ran DISABLE_JSON_MODE=1; current scan.py hardcodes json_mode for triage.
# Match the author + avoid backend response_format issues: force json_mode off
# (the triage prompt still asks for JSON in text; _extract_json parses it).
_orig_call = A.call_llm
def _call(model, messages, keys, json_mode=False, max_retries=3, reasoning_effort=None):
    return _orig_call(model, messages, keys, json_mode=False,
                      max_retries=max_retries, reasoning_effort=reasoning_effort)
A.call_llm = _call

MODEL   = "google/gemma-4-31b-it"
CODE    = open("/tmp/fb-fix-test/sys/rpc/rpcsec_gss/svc_rpcsec_gss.c").read()
DISPLAY = "rpcsec_gss/svc_rpcsec_gss.c"
REPO    = "/tmp/fb-fix-test/sys/rpc"
ROUNDS  = 3            # author's run-aisle.sh setting
N       = 5            # independent triage trials on the SAME fixed finding

A.init_api_semaphore(1)
A.init_grep_index(REPO)
keys = A.load_api_keys()

# --- extract the CVE finding from a HIT scan report ---
report = open("run1-reproducibility/report_00.md").read()
findings = A.extract_findings(report)   # list of (title, text)
cve = next(((t, x) for (t, x) in findings
            if re.search(r"svc_rpc_gss_validate|rpchdr", t + x, re.I)), None)
if not cve:
    raise SystemExit("could not find the CVE finding in the report")
TITLE, TEXT = cve
print(f"CVE finding under triage: {TITLE[:80]!r}\n", flush=True)

def one_triage_trial():
    """Replicate scan.py's _triage_one_finding_inner: ROUNDS rounds + arbiter."""
    round_verdicts, prior = [], None
    for rn in range(1, ROUNDS + 1):
        tv = A.triage_finding(TITLE, TEXT, CODE, DISPLAY, "rpc", MODEL, keys,
                              prior_reasoning=prior, repo_dir=REPO, file_context=None)
        tv["round"] = rn
        round_verdicts.append(tv)
        if prior is None:
            prior = []
        rtext = tv.get("reasoning", "")
        greps = A.execute_grep_requests(rtext, REPO)
        if prior:
            prior = [(v, A._condense_prior_greps(r)) for v, r in prior]
        if greps:
            rtext += f"\n\n[GREP RESULTS]:\n{greps}"
        prior.append((tv["verdict"], rtext))

    n_valid = sum(1 for rv in round_verdicts if rv["verdict"] == "VALID")
    n_invalid = sum(1 for rv in round_verdicts if rv["verdict"] == "INVALID")
    n_total = len(round_verdicts)
    vstr = "".join(rv["verdict"][0] for rv in round_verdicts)

    # arbiter
    evidence = []
    for rv in round_verdicts:
        s = rv.get("reasoning", "")[:500]
        cm = re.search(r"CRUX:\s*(.+?)(?:\n|$)", rv.get("reasoning", ""))
        evidence.append(f"**Round {rv['round']} ({rv['verdict']}):** {s}" + (f"\nCRUX: {cm.group(1).strip()}" if cm else ""))
    arb_prompt = (f"A vulnerability was reported in rpc:\n{TITLE}\n\nThe reported finding:\n{TEXT}\n\n"
                  f"Key evidence from {n_total} rounds of analysis:\n" + "\n".join(evidence[:10]) +
                  f"\n\nVerdicts so far: {vstr} ({n_valid} valid, {n_invalid} invalid)\n\n"
                  f"The relevant source code from {DISPLAY}:\n```c\n{CODE}\n```\n\n"
                  "Based on the code and evidence, is this a real security vulnerability? "
                  "Verify any numeric values yourself from the code.\n\n"
                  + ("NOTE: All prior reviewers said UNCERTAIN or INVALID. Only override to VALID if overwhelming.\n\n" if n_valid == 0 else "")
                  + 'Respond with JSON: {"verdict": "VALID/INVALID", "reasoning": "concise"}')
    final = round_verdicts[-1]["verdict"]
    try:
        ar, _, _ = A.call_llm(MODEL, [{"role": "system", "content": "You are an impartial judge. Decide based on evidence, not arguments."},
                                      {"role": "user", "content": arb_prompt}], keys, json_mode=False)
        ap = A._extract_json(ar)
        if isinstance(ap, dict):
            av = ap.get("verdict", "").upper()
            if av in ("VALID", "INVALID"):
                vstr += "→" + av[0]
                if av == "VALID": n_valid += 1
                else: n_invalid += 1
                n_total += 1
                final = av
    except Exception as e:
        vstr += "→(arb err)"
    conf = round(n_valid / n_total, 2) if n_total else 0
    return vstr, final, conf

print(f"running N={N} triage trials ({ROUNDS} rounds + arbiter each) on {MODEL} via {URL}\n", flush=True)
survived = 0
for i in range(N):
    vstr, final, conf = one_triage_trial()
    ok = (final == "VALID")
    survived += ok
    print(f"[{i:02d}] rounds={vstr}  FINAL={final}  conf={conf}  {'SURVIVES' if ok else 'DROPPED'}", flush=True)
print(f"\nSURVIVED TRIAGE: {survived}/{N}", flush=True)
print("DONE", flush=True)
