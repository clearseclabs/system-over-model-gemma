"""The tweak: a reachability-strict arbiter stage. Run each of Run-1's 30 auto-'VALID'
findings back through Gemma with a precision-first prompt that forces it to trace from an
external entry point, GREP for callers/constants, and REJECT dead-code / kernel-set /
not-attacker-reachable findings. Measures how far the false-positive count collapses.
"""
import os, re, glob, importlib.util, concurrent.futures, traceback

spec = importlib.util.spec_from_file_location("aisle_scan", "/tmp/aisle_scan.py")
A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
URL = os.environ["OPENWEBUI_URL"].rstrip("/") + "/api/chat/completions"
A.OPENROUTER_API_URL = URL; os.environ["OPENROUTER_API_KEY"] = os.environ["OPENWEBUI_API_KEY"]
_r=A.resolve_backend; A.resolve_backend=lambda m,k:(lambda u,kk,n,h:(u,kk,n,{**h,"User-Agent":"OpenAI/Python 1.51.0"}))(*_r(m,k))
_c=A.call_llm; A.call_llm=lambda model,messages,keys,json_mode=False,max_retries=3,reasoning_effort=None:_c(model,messages,keys,json_mode=False,max_retries=max_retries,reasoning_effort=reasoning_effort)

MODEL="google/gemma-4-31b-it"
REPO="/tmp/fb-fix-test/sys/rpc"
FINDINGS=sorted(glob.glob("results-aisle-gemma-sysrpc/findings/VULN-*.md"))
A.init_api_semaphore(10); A.init_grep_index(REPO)
keys=A.load_api_keys()

SYS=("You are a PRECISION-FIRST reachability arbiter for FreeBSD kernel C. An automated funnel "
"graduated the finding below as 'VALID'. REJECT it unless it is a genuinely attacker-reachable bug. "
"Mark VALID only if ALL hold: (1) the bug pattern really exists in the cited code; (2) a concrete path "
"runs from an EXTERNAL entry point (network packet or userspace syscall) to the sink carrying "
"ATTACKER-CONTROLLED data; (3) the cited length/pointer/value is actually attacker-controlled — NOT "
"kernel-set (e.g. sockaddr sa_len), NOT bounded upstream (e.g. MAX_AUTH_BYTES), NOT a fixed-size field. "
"Mark INVALID if: the function has no callers (dead code), the value is kernel-generated or bounded, the "
"trigger needs a privileged/local-only actor, or you cannot establish a concrete reachable path. Use GREP "
"to find callers and confirm constants — never guess. Under uncertainty, default INVALID.")

def src_for(text):
    m=re.search(r"File\W*`([^`]+)`", text)
    cand=m.group(1) if m else None
    paths=[]
    if cand:
        p=os.path.join(REPO,cand)
        paths=[p] if os.path.exists(p) else glob.glob(os.path.join(REPO,"**",os.path.basename(cand)),recursive=True)
    if not paths: return cand,None
    return os.path.relpath(paths[0],REPO), open(paths[0],errors="replace").read()

def prompt(title, body, rel, code, extra=""):
    ctx = code[:16000] if code else "(source not found — if you cannot see the code or its callers, default INVALID)"
    return (f"FINDING (auto-graduated VALID):\n{title}\n{body[:1400]}\n\nSOURCE {rel}:\n```c\n{ctx}\n```\n{extra}\n"
            "Trace BACKWARD from the sink to an external entry point. To check callers/constants emit lines like  "
            "GREP: <pattern>  (e.g. GREP: svc_rpc_gss_validate to find callers). "
            'Then answer JSON: {"verdict":"VALID|INVALID","entry_point":"<path from untrusted input, or NONE>","why":"<=2 sentences"}')

def arbiter(path):
    name=os.path.basename(path).replace(".md","")
    try:
        txt=open(path,errors="replace").read()
        mt=re.search(r"^#\s*(.+)",txt,re.M); title=mt.group(1) if mt else name
        rel,code=src_for(txt)
        r1,_,_=A.call_llm(MODEL,[{"role":"system","content":SYS},{"role":"user","content":prompt(title,txt,rel,code)}],keys)
        greps=A.execute_grep_requests(r1,REPO)
        extra=(f"\n[Your prior analysis]:\n{r1[:700]}\n[GREP RESULTS — caller/constant facts]:\n"
               f"{(greps or '(no matches found — likely no callers / constant absent)')[:1500]}\nRe-decide strictly using these facts.")
        r2,_,_=A.call_llm(MODEL,[{"role":"system","content":SYS},{"role":"user","content":prompt(title,txt,rel,code,extra)}],keys)
        p=A._extract_json(r2) or A._extract_json(r1) or {}
        v=(p.get("verdict","") or "").upper()
        if v not in ("VALID","INVALID"): v="UNCERTAIN"
        return (name, rel or "?", v, (p.get("entry_point","") or "")[:48], (p.get("why","") or "")[:140])
    except Exception as e:
        return (name, "?", "ERR", "", (str(e)+traceback.format_exc()[-80:])[:140])

print(f"reachability-strict arbiter (THE TWEAK) on {len(FINDINGS)} Run-1 auto-VALID findings | model={MODEL} | 10 parallel\n", flush=True)
res=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
    futs={ex.submit(arbiter,p):p for p in FINDINGS}
    for f in concurrent.futures.as_completed(futs):
        r=f.result(); res.append(r)
        print(f"[{r[0]:36}] {r[2]:8} src={r[1]:30} entry={r[3]}", flush=True)
v=sum(1 for r in res if r[2]=="VALID"); inv=sum(1 for r in res if r[2]=="INVALID"); u=len(res)-v-inv
print(f"\n=== TWEAK RESULT: {len(res)} auto-'VALID' findings -> arbiter keeps {v} VALID, rejects {inv} INVALID, {u} uncertain/err ===")
print("SURVIVORS (still VALID):")
for r in sorted(res):
    if r[2]=="VALID": print(f"  {r[0]} ({r[1]}): {r[4]}")
print("DONE", flush=True)
