import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, jsonify, render_template, request

import checker

app = Flask(__name__)
MAX_ADDRESSES = 50


def parse_addresses(text):
    """Split pasted text on whitespace, commas and semicolons; drop duplicates."""
    seen, out = set(), []
    for token in re.split(r"[\s,;]+", text or ""):
        token = token.strip("<>\"'()[]").removeprefix("mailto:")
        if token and token.lower() not in seen:
            seen.add(token.lower())
            out.append(token)
    return out


@app.get("/")
def index():
    return render_template("index.html", smtp=checker.smtp_available(), max_addresses=MAX_ADDRESSES)


@app.post("/check")
def check():
    addresses = parse_addresses((request.get_json(silent=True) or {}).get("text", ""))
    if not addresses:
        return jsonify(error="Paste at least one email address."), 400
    if len(addresses) > MAX_ADDRESSES:
        return jsonify(error=f"Please check {MAX_ADDRESSES} addresses or fewer at a time."), 400

    probe = checker.smtp_available()
    groups = defaultdict(list)
    for a in addresses:
        groups[a.rsplit("@", 1)[-1].lower()].append(a)

    with ThreadPoolExecutor(max_workers=8) as pool:
        done = list(pool.map(lambda g: checker.check_group(g, probe), groups.values()))
    by_address = {r["address"]: r for group in done for r in group}
    return jsonify(results=[by_address[a] for a in addresses], smtp=probe)


if __name__ == "__main__":
    app.run(debug=True)
