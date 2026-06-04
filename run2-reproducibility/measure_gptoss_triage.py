import os, re, importlib.util
spec = importlib.util.spec_from_file_location("aisle_scan", "/tmp/aisle_scan.py")
A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
URL = os.environ["OPENWEBUI_URL"].rstrip("/") + "/api/chat/completions"
A.OPENROUTER_API_URL = URL; os.environ["OPENROUTER_API_KEY"] = os.environ["OPENWEBUI_API_KEY"]
_r=A.resolve_backend; A.resolve_backend=lambda m,k:(lambda u,kk,n,h:(u,kk,n,{**h,"User-Agent":"OpenAI/Python 1.51.0"}))(*_r(m,k))
_c=A.call_llm; A.call_llm=lambda model,messages,keys,json_mode=False,max_retries=3,reasoning_effort=None:_c(model,messages,keys,json_mode=False,max_retries=max_retries,reasoning_effort=reasoning_effort)
MODEL="openai/gpt-oss-20b"; CODE=open("/tmp/fb-fix-test/sys/rpc/rpcsec_gss/svc_rpcsec_gss.c").read()
DISPLAY="rpcsec_gss/svc_rpcsec_gss.c"; REPO="/tmp/fb-fix-test/sys/rpc"; ROUNDS=3; N=6
A.init_api_semaphore(3); A.init_grep_index(REPO); keys=A.load_api_keys()
rep=open("/tmp/run2measure/scan/report_01.md").read()
TITLE,TEXT=next((t,x) for t,x in A.extract_findings(rep) if re.search(r"svc_rpc_gss_validate|rpchdr",t+x,re.I))
print(f"### gpt-oss TRIAGE reproducibility (N={N}, {ROUNDS} rounds+arbiter) on a HIT finding ###\nfinding: {TITLE[:80]!r}\n",flush=True)
def trial():
    rv=[];prior=None
    for rn in range(1,ROUNDS+1):
        tv=A.triage_finding(TITLE,TEXT,CODE,DISPLAY,"rpc",MODEL,keys,prior_reasoning=prior,repo_dir=REPO,file_context=None)
        tv["round"]=rn;rv.append(tv)
        if prior is None: prior=[]
        rt=tv.get("reasoning","");g=A.execute_grep_requests(rt,REPO)
        if prior: prior=[(v,A._condense_prior_greps(r)) for v,r in prior]
        if g: rt+=f"\n\n[GREP RESULTS]:\n{g}"
        prior.append((tv["verdict"],rt))
    nv=sum(v["verdict"]=="VALID" for v in rv);ni=sum(v["verdict"]=="INVALID" for v in rv);nt=len(rv)
    vs="".join(v["verdict"][0] for v in rv)
    ev=[f"**Round {v['round']} ({v['verdict']}):** {v.get('reasoning','')[:400]}" for v in rv]
    ap=(f"A vulnerability was reported in rpc:\n{TITLE}\n\nThe reported finding:\n{TEXT}\n\nKey evidence from {nt} rounds:\n"+"\n".join(ev)+
        f"\n\nVerdicts so far: {vs} ({nv} valid, {ni} invalid)\n\nThe relevant source from {DISPLAY}:\n```c\n{CODE}\n```\n\nIs this a real security vulnerability? Verify numeric values yourself.\n\n"
        +("NOTE: all prior reviewers said UNCERTAIN/INVALID. Override to VALID only if overwhelming.\n\n" if nv==0 else "")+'Respond with JSON: {"verdict":"VALID/INVALID","reasoning":"concise"}')
    final=rv[-1]["verdict"]
    try:
        ar,_,_=A.call_llm(MODEL,[{"role":"system","content":"You are an impartial judge. Decide based on evidence, not arguments."},{"role":"user","content":ap}],keys)
        p=A._extract_json(ar)
        if isinstance(p,dict) and p.get("verdict","").upper() in ("VALID","INVALID"): final=p["verdict"].upper(); vs+="→"+final[0]
        else: vs+="→(unparsed)"
    except Exception as e: vs+="→(err)"
    return vs,final
surv=0
for i in range(N):
    try:
        vs,final=trial();ok=(final=="VALID");surv+=ok
        print(f"[tri {i:02d}] rounds={vs}  FINAL={final}  {'SURVIVES' if ok else 'DROPPED'}",flush=True)
    except Exception as e: print(f"[tri {i:02d}] EXC: {e}",flush=True)
print(f"\nSURVIVED TRIAGE: {surv}/{N}\nDONE",flush=True)
