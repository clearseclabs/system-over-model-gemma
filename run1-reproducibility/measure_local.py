"""Same faithful AISLE two-stage scan as measure_run1.py, but pointed at the
LOCAL MLX-quantized Gemma (localhost:1234) instead of the hosted OpenRouter model.
Tests whether the low-bit local quant invents the bounds check more often.
"""
import os, importlib.util, pathlib, traceback

spec = importlib.util.spec_from_file_location("aisle_scan", "/tmp/aisle_scan.py")
aisle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aisle)

LOCAL = "http://localhost:1234/v1/chat/completions"
aisle.OPENAI_API_URL = LOCAL
aisle.OPENROUTER_API_URL = LOCAL          # patch both so either route hits local
os.environ["OPENAI_API_KEY"] = "lm-studio"
os.environ["OPENROUTER_API_KEY"] = "lm-studio"

# local 31B generation is slow -> raise the 120s timeout baked into call_llm
_sess = aisle._get_session()
_orig_open = _sess.open
def _open(fullurl, data=None, timeout=120):
    return _orig_open(fullurl, data, 900)
_sess.open = _open

MODEL   = "gemma-4-31b-it-mlx"            # no "/" -> OpenAI branch -> patched LOCAL url
FILE    = "/tmp/fb-fix-test/sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"
REPO    = "/tmp/fb-fix-test/sys/rpc"
DISPLAY = "rpcsec_gss/svc_rpcsec_gss.c"
N       = 5

aisle.init_api_semaphore(1)               # one local GPU; serialize
aisle.init_grep_index(REPO)               # rg present -> grep-as-tool works, faithful
code = open(FILE).read()
keys = aisle.load_api_keys()
outdir = pathlib.Path("/tmp/run1local"); outdir.mkdir(exist_ok=True)

print(f"N={N} faithful AISLE scans on {DISPLAY} via LOCAL {MODEL} @ {LOCAL}", flush=True)
for i in range(N):
    if (outdir / f"report_{i:02d}.md").exists():
        print(f"[{i:02d}] skip (already have it)", flush=True); continue
    last = None
    for attempt in range(2):
        try:
            r = aisle.scan_single_file(FILE, code, DISPLAY, MODEL, keys, repo_dir=REPO)
            if r.get("status") == "ok":
                (outdir / f"report_{i:02d}.md").write_text(r["report"])
                print(f"[{i:02d}] ok  sev={r.get('severities')}  chars={len(r['report'])}  "
                      f"ctx={r.get('context_elapsed')}s scan={r.get('scan_elapsed')}s", flush=True)
                last = None
                break
            last = r.get("error")
        except Exception as e:
            last = f"{e} | {traceback.format_exc()[-200:]}"
    if last:
        print(f"[{i:02d}] ERROR: {last}", flush=True)
print("DONE", flush=True)
