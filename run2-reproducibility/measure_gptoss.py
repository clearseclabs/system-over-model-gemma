"""gpt-oss-20b reproducibility: scan + triage, faithful AISLE scan.py, via OpenRouter.

Part A: scan svc_rpcsec_gss.c N times -> does gpt-oss flag the rpchdr overflow? rate.
Part B: take the CVE finding from a HIT scan, run AISLE's 3-round+arbiter triage N
        times -> does it SURVIVE, or does the vote drop it (Run 2's claim)? Captures
        per-round verdicts so we can see parse-failures (harmony tokens) vs reasoning.
"""
import os, re, importlib.util, pathlib, traceback

spec = importlib.util.spec_from_file_location("aisle_scan", "/tmp/aisle_scan.py")
A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)

URL = os.environ["OPENWEBUI_URL"].rstrip("/") + "/api/chat/completions"
A.OPENROUTER_API_URL = URL
os.environ["OPENROUTER_API_KEY"] = os.environ["OPENWEBUI_API_KEY"]
_r = A.resolve_backend
A.resolve_backend = lambda m,k:(lambda u,kk,n,h:(u,kk,n,{**h,"User-Agent":"OpenAI/Python 1.51.0"}))(*_r(m,k))
# match author's DISABLE_JSON_MODE=1 + avoid backend json issues
_c = A.call_llm
A.call_llm = lambda model,messages,keys,json_mode=False,max_retries=3,reasoning_effort=None: _c(model,messages,keys,json_mode=False,max_retries=max_retries,reasoning_effort=reasoning_effort)

MODEL   = "openai/gpt-oss-20b"
CODE    = open("/tmp/fb-fix-test/sys/rpc/rpcsec_gss/svc_rpcsec_gss.c").read()
DISPLAY = "rpcsec_gss/svc_rpcsec_gss.c"
REPO    = "/tmp/fb-fix-test/sys/rpc"
N_SCAN, N_TRI, ROUNDS = 8, 8, 3
A.init_api_semaphore(3); A.init_grep_index(REPO)
keys = A.load_api_keys()
outdir = pathlib.Path("/tmp/run2measure"); (outdir/"scan").mkdir(parents=True, exist_ok=True)

CATCH = re.compile(r"(no (bounds?|upper)?.{0,6}check|without (bounds|validating|checking)|unbounded|no upper.?bound)", re.I)
INVENT= re.compile(r"(sizeof\(rpchdr\)\s*-\s*8|MAX_AUTH_BYTES.{0,30}(128|guarantee|ensure|limit)|limited to 96|bounded to 96|xdr_opaque_auth.{0,40}(guarantee|limit))", re.I)

print(f"### PART A: gpt-oss SCAN reproducibility (N={N_SCAN}) ###", flush=True)
hit_report = None; scan_hits = 0
for i in range(N_SCAN):
    try:
        r = A.scan_single_file("x", CODE, DISPLAY, MODEL, keys, repo_dir=REPO)
        if r.get("status") != "ok":
            print(f"[scan {i:02d}] ERROR: {r.get('error')}", flush=True); continue
        rep = r["report"]; (outdir/"scan"/f"report_{i:02d}.md").write_text(rep)
        # does it flag the svc_rpc_gss_validate rpchdr overflow as unbounded, w/o inventing a bound?
        seg = rep
        flags = bool(re.search(r"svc_rpc_gss_validate|rpchdr", seg, re.I)) and bool(CATCH.search(seg))
        invented = bool(INVENT.search(seg))
        verdict = "HIT" if (flags and not invented) else ("MISS(invent)" if invented else "MISS")
        if verdict == "HIT": scan_hits += 1; hit_report = hit_report or rep
        print(f"[scan {i:02d}] {verdict}  sev={r.get('severities')}", flush=True)
    except Exception as e:
        print(f"[scan {i:02d}] EXC: {e}", flush=True)
print(f"SCAN HITS: {scan_hits}/{N_SCAN}\n", flush=True)

# --- pick the CVE finding for triage (from a gpt-oss HIT scan, else cached Run-2) ---
def cve_finding(report_text):
    for t,x in A.extract_findings(report_text):
        if re.search(r"svc_rpc_gss_validate|rpchdr", t+x, re.I): return t,x
    return None
fin = cve_finding(hit_report) if hit_report else None
if not fin:
    cached = "results-aisle-gpt-oss-sysrpc/rpcsec_gss_svc_rpcsec_gss.c.md"
    if os.path.exists(cached): fin = cve_finding(open(cached).read())
if not fin:
    print("no CVE finding available for triage; stopping after scan."); raise SystemExit(0)
TITLE, TEXT = fin
print(f"### PART B: gpt-oss TRIAGE reproducibility (N={N_TRI}, {ROUNDS} rounds+arbiter) ###")
print(f"finding: {TITLE[:80]!r}\n", flush=True)

def triage_trial():
    rv=[]; prior=None
    for rn in range(1,ROUNDS+1):
        tv=A.triage_finding(TITLE,TEXT,CODE,DISPLAY,"rpc",MODEL,keys,prior_reasoning=prior,repo_dir=REPO,file_context=None)
        tv["round"]=rn; rv.append(tv)
        if prior is None: prior=[]
        rt=tv.get("reasoning",""); g=A.execute_grep_requests(rt,REPO)
        if prior: prior=[(v,A._condense_prior_greps(r)) for v,r in prior]
        if g: rt+=f"\n\n[GREP RESULTS]:\n{g}"
        prior.append((tv["verdict"],rt))
    nv=sum(v["verdict"]=="VALID" for v in rv); ni=sum(v["verdict"]=="INVALID" for v in rv); nt=len(rv)
    vs="".join(v["verdict"][0] for v in rv)
    ev=[]
    for v in rv:
        cm=re.search(r"CRUX:\s*(.+?)(?:\n|$)",v.get("reasoning",""))
        ev.append(f"**Round {v['round']} ({v['verdict']}):** {v.get('reasoning','')[:500]}"+(f"\nCRUX:{cm.group(1).strip()}" if cm else ""))
    ap=(f"A vulnerability was reported in rpc:\n{TITLE}\n\nThe reported finding:\n{TEXT}\n\n"
        f"Key evidence from {nt} rounds:\n"+"\n".join(ev[:10])+f"\n\nVerdicts so far: {vs} ({nv} valid, {ni} invalid)\n\n"
        f"The relevant source code from {DISPLAY}:\n```c\n{CODE}\n```\n\nBased on the code and evidence, is this a real security vulnerability? Verify numeric values yourself.\n\n"
        +("NOTE: all prior reviewers said UNCERTAIN/INVALID. Only override to VALID if overwhelming.\n\n" if nv==0 else "")
        +'Respond with JSON: {"verdict": "VALID/INVALID", "reasoning": "concise"}')
    final=rv[-1]["verdict"]
    try:
        ar,_,_=A.call_llm(MODEL,[{"role":"system","content":"You are an impartial judge. Decide based on evidence, not arguments."},{"role":"user","content":ap}],keys)
        p=A._extract_json(ar)
        if isinstance(p,dict) and p.get("verdict","").upper() in ("VALID","INVALID"):
            av=p["verdict"].upper(); vs+="→"+av[0]; final=av
            if av=="VALID": nv+=1
    except Exception: vs+="→(arb?)"
    return vs, final, round(nv/max(1,(nt+(1 if "→" in vs else 0))),2)

surv=0
for i in range(N_TRI):
    try:
        vs,final,conf=triage_trial(); ok=(final=="VALID"); surv+=ok
        print(f"[tri {i:02d}] rounds={vs}  FINAL={final}  {'SURVIVES' if ok else 'DROPPED'}", flush=True)
    except Exception as e:
        print(f"[tri {i:02d}] EXC: {e}", flush=True)
print(f"\nSURVIVED TRIAGE: {surv}/{N_TRI}\nDONE", flush=True)
