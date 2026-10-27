# Email address checker

Paste a list of email addresses and see whether each one is **likely delivered**, **likely to bounce**, or **unknown**. The tool never sends a message to anyone.

## How it works

Each address goes through three layers and stops at the first verdict.

1. **Syntax check.** Malformed addresses (no `@`, bad characters, bad domain) are marked *likely to bounce*.
2. **DNS lookup.** The tool asks DNS for the domain's MX records, which say where its mail is received. If the domain doesn't exist, has no mail server, or publishes a null MX, the address is marked *likely to bounce*. If DNS itself fails or times out, the result is *unknown*.
3. **SMTP probe.** The tool connects to the domain's mail server on port 25 and runs `EHLO`, `MAIL FROM`, `RCPT TO`, then disconnects. It never reaches the `DATA` step, so no message is delivered.
   - `250` (accepted): *likely delivered*
   - `550`/`551`/`553` saying the mailbox doesn't exist: *likely to bounce*
   - Temporary errors, greylisting, timeouts, or refusals that look like spam/policy blocks: *unknown*
   - **Catch-all test:** after an acceptance, the tool asks the same server about a random made-up address on that domain. If that is accepted too, the server says yes to everything, so the result is downgraded to *unknown*.

**Why "unknown" is normal.** Many mail servers, including large providers, won't confirm whether a mailbox exists, or accept every address. In those cases the honest answer is "unknown", and the interface says so.

Politeness limits: at most 50 addresses per request, 8-second connection timeouts, only the first two mail servers per domain are tried, and probes to the same domain are spaced one second apart.

## What the deployed version can and cannot check

Free hosts block outbound connections to mail servers. Render's free web services block ports 25, 465 and 587, and port 25 stays blocked on its paid plans too. Railway's free and Hobby plans block SMTP as well.

On startup the app tests whether port 25 is reachable. If not, it switches to **DNS-only mode** and shows a banner saying so.

| | Local (port 25 open) | Deployed on a free host |
|---|---|---|
| Syntax check | Yes | Yes |
| Domain and MX lookup | Yes | Yes |
| Mailbox-level SMTP probe | Yes | **No** |
| Catch-all detection | Yes | **No** |

In DNS-only mode, bad syntax and dead domains are still reported as *likely to bounce*, but an address that passes both checks is reported as *unknown*, because the tool can't say whether the mailbox exists. Run it locally to get the full check.

Some home and office networks and cloud providers also block port 25. If so, you'll see the same banner locally.

## Run it locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py            # http://127.0.0.1:5000
```

Optional environment variables:

- `MAIL_FROM`: the sender address used in the probe. Use an address on a domain you control; some servers reject probes from unresolvable domains.
- `HELO_HOST`: the hostname announced to mail servers (defaults to this machine's name).
- `SMTP_PROBE`: `auto` (default, detects port 25), `on`, or `off`.
- `SMTP_TIMEOUT`, `PROBE_DELAY`: connection timeout and delay between probes to one domain, in seconds.

Run the tests with `python -m unittest discover`. They mock the network, so they run anywhere.

## Deploy on Render

1. Push this repository to GitHub.
2. In Render, choose **New > Blueprint** (or **New > Web Service**) and select the repo. `render.yaml` sets the build and start commands and the free plan.
3. Open the `onrender.com` URL once deployed. The first request after idle time can take 30 to 60 seconds.

## Responsible use

Only check addresses you have a reason to check. The probe contacts third-party mail servers, so don't run it against large lists you don't own, and don't use it to send messages.

## Files

- `app.py`: Flask routes and input parsing
- `checker.py`: syntax, DNS and SMTP logic
- `templates/index.html`: the single-page interface
- `tests/`: unit tests
- `render.yaml`: Render deployment config
