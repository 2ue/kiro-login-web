#!/usr/bin/env python3
import argparse, json, statistics, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from playwright.sync_api import sync_playwright


def run_one(i: int, hold: float) -> dict:
    t0 = time.time()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            page = browser.new_page()
            page.goto("data:text/html,<title>probe</title><h1>ok</h1>", wait_until="domcontentloaded", timeout=15000)
            title = page.title()
            time.sleep(hold)
            browser.close()
        return {"idx": i, "ok": True, "ms": int((time.time()-t0)*1000), "title": title}
    except Exception as e:
        return {"idx": i, "ok": False, "ms": int((time.time()-t0)*1000), "error": str(e)[:300]}


def probe(n: int, hold: float) -> dict:
    t0 = time.time()
    rows = []
    with ThreadPoolExecutor(max_workers=n) as ex:
        futs = [ex.submit(run_one, i, hold) for i in range(1, n+1)]
        for f in as_completed(futs):
            rows.append(f.result())
    oks = [r["ms"] for r in rows if r["ok"]]
    return {
        "concurrency": n,
        "ok": sum(1 for r in rows if r["ok"]),
        "fail": sum(1 for r in rows if not r["ok"]),
        "total_ms": int((time.time()-t0)*1000),
        "p50_ms": int(statistics.median(oks)) if oks else None,
        "max_ms": max(oks) if oks else None,
        "errors": [r for r in rows if not r["ok"]][:3],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--levels", default="6,10,15,20")
    ap.add_argument("--hold", type=float, default=3.0)
    args = ap.parse_args()
    for n in [int(x) for x in args.levels.split(",") if x.strip()]:
        print(json.dumps(probe(n, args.hold), ensure_ascii=False), flush=True)

if __name__ == "__main__":
    main()
