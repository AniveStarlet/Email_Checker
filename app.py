import json
import logging
import queue
import re
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, Response, jsonify, render_template, request, stream_with_context
from werkzeug.exceptions import HTTPException

import checker

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
app = Flask(__name__)
MAX_ADDRESSES = 50


def parse_addresses(text):
    """Split pasted text on whitespace, commas and semicolons; drop duplicates."""
    seen, out = set(), []
    for token in re.split(r"[\s,;]+", text or ""):
        token = token.strip("<>\"'()[]")
        if token.lower().startswith("mailto:"):
            token = token[7:]
        if token and token.lower() not in seen:
            seen.add(token.lower())
            out.append(token)
    return out


def _probe_enabled():
    try:
        return checker.smtp_available()
    except Exception:
        return False


def _read_request():
    """Return (addresses, error_message)."""
    addresses = parse_addresses((request.get_json(silent=True) or {}).get("text", ""))
    if not addresses:
        return None, "Paste at least one email address."
    if len(addresses) > MAX_ADDRESSES:
        return None, f"Please check {MAX_ADDRESSES} addresses or fewer at a time."
    return addresses, None


def _by_domain(addresses):
    groups = defaultdict(list)
    for a in addresses:
        groups[a.rsplit("@", 1)[-1].lower()].append(a)
    return groups


@app.errorhandler(Exception)
def on_error(exc):
    if isinstance(exc, HTTPException):
        return exc
    app.logger.exception("Unhandled error")
    if request.path.startswith("/check"):
        return jsonify(error="The check failed on the server. Try fewer addresses."), 500
    return "Something went wrong. Check the server logs.", 500


@app.get("/")
def index():
    return render_template("index.html", smtp=_probe_enabled(), max_addresses=MAX_ADDRESSES)


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/favicon.ico")
def favicon():
    return "", 204  # the page supplies its own icon; this just stops 404s


@app.post("/check")
def check():
    addresses, error = _read_request()
    if error:
        return jsonify(error=error), 400
    probe = _probe_enabled()
    groups = _by_domain(addresses)
    with ThreadPoolExecutor(max_workers=8) as pool:
        done = list(pool.map(lambda g: checker.check_group(g, probe), groups.values()))
    by_address = {r["address"]: r for group in done for r in group}
    return jsonify(results=[by_address[a] for a in addresses], smtp=probe)


@app.post("/check/stream")
def check_stream():
    """Same as /check, but sends one JSON line per result as soon as it is ready."""
    addresses, error = _read_request()
    if error:
        return jsonify(error=error), 400
    probe = _probe_enabled()
    groups = _by_domain(addresses)
    started = time.time()
    checker.log_event("request", count=len(addresses), domains=len(groups), smtp=probe)

    results = queue.Queue()

    def work(group):
        try:
            for r in checker.iter_group(group, probe):
                results.put(r)
        finally:
            results.put(None)  # this group is finished

    pool = ThreadPoolExecutor(max_workers=8)
    for g in groups.values():
        pool.submit(work, g)
    pool.shutdown(wait=False)

    def generate():
        yield json.dumps({"smtp": probe, "addresses": addresses}) + "\n"
        finished = 0
        while finished < len(groups):
            item = results.get()
            if item is None:
                finished += 1
            else:
                yield json.dumps(item) + "\n"
        checker.log_event("request_done", count=len(addresses), seconds=round(time.time() - started, 1))

    return Response(stream_with_context(generate()), mimetype="application/x-ndjson",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


if __name__ == "__main__":
    app.run(debug=True)
