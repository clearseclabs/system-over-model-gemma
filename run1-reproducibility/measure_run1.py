"""Measure how often Run 1's scan-stage miss reproduces.

Imports AISLE's real scan.py, points its backend at the OpenWebUI/OpenRouter
proxy, and runs the genuine two-stage scan (context -> broad scan + few-shot)
N times on the unpatched svc_rpcsec_gss.c, capturing each stage-2 report.
"""
import os, importlib.util, pathlib, concurrent.futures, traceback

spec = importlib.util.spec_from_file_location("aisle_scan", "/tmp/aisle_scan.py")
aisle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aisle)

# --- point AISLE's backend at the OpenWebUI proxy, with a real User-Agent ---
URL = os.environ["OPENWEBUI_URL"].rstrip("/") + "/api/chat/completions"
aisle.OPENROUTER_API_URL = URL
os.environ["OPENROUTER_API_KEY"] = os.environ["OPENWEBUI_API_KEY"]

_orig_resolve = aisle.resolve_backend
def _resolve(model, keys):
    u, k, n, h = _orig_resolve(model, keys)
    return u, k, n, {**h, "User-Agent": "OpenAI/Python 1.51.0"}
aisle.resolve_backend = _resolve

MODEL   = "google/gemma-4-31b-it"
FILE    = "/tmp/fb-fix-test/sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"   # unpatched
REPO    = "/tmp/fb-fix-test/sys/rpc"
DISPLAY = "rpcsec_gss/svc_rpcsec_gss.c"
N       = 12
WORKERS = 4

aisle.init_api_semaphore(WORKERS)
aisle.init_grep_index(REPO)
code = open(FILE).read()
keys = aisle.load_api_keys()
outdir = pathlib.Path("/tmp/run1measure"); outdir.mkdir(exist_ok=True)

def trial(i):
    last = None
    for attempt in range(3):
        try:
            r = aisle.scan_single_file(FILE, code, DISPLAY, MODEL, keys, repo_dir=REPO)
            if r.get("status") == "ok":
                (outdir / f"report_{i:02d}.md").write_text(r["report"])
                sev = r.get("severities", {})
                return f"[{i:02d}] ok  sev={sev} report_chars={len(r['report'])}"
            last = r.get("error")
        except Exception as e:
            last = f"{e}\n{traceback.format_exc()[-300:]}"
    return f"[{i:02d}] ERROR after retries: {last}"

print(f"running N={N} faithful AISLE scans on {DISPLAY} via {URL}", flush=True)
with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as ex:
    futs = [ex.submit(trial, i) for i in range(N)]
    for f in concurrent.futures.as_completed(futs):
        print(f.result(), flush=True)
print("DONE", flush=True)
