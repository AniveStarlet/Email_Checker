"""Email address checker.

Layers, stopping at the first verdict:
  1. Syntax check
  2. DNS lookup (MX records, falling back to A/AAAA)
  3. SMTP probe: RCPT TO only, then disconnect. No message is ever sent.
"""
import os
import random
import re
import smtplib
import socket
import string
import threading
import time

import dns.exception
import dns.resolver

DELIVERED = "delivered"
BOUNCE = "bounce"
UNKNOWN = "unknown"

DNS_TIMEOUT = 5
SMTP_TIMEOUT = float(os.environ.get("SMTP_TIMEOUT", "8"))
DELAY_BETWEEN_PROBES = float(os.environ.get("PROBE_DELAY", "1"))
HELO_HOST = os.environ.get("HELO_HOST") or socket.getfqdn() or "localhost"
MAIL_FROM = os.environ.get("MAIL_FROM") or f"verify@{HELO_HOST}"
PORT25_TEST_HOSTS = ["gmail-smtp-in.l.google.com", "aspmx.l.google.com"]

LOCAL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$")
LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

# A 5xx answer containing these words is the server refusing *us*, not
# saying the mailbox is missing, so it must not be reported as a bounce.
POLICY_WORDS = ("spam", "block", "blacklist", "denied", "policy", "rbl",
                "reputation", "blocked", "listed", "5.7.", "not allowed",
                "relay", "authenticat", "greylist")


def check_syntax(address):
    """Return an error string, or None if the address looks valid."""
    if address.count("@") != 1:
        return "Must contain exactly one @"
    local, domain = address.split("@")
    if not local or not domain:
        return "Missing the part before or after the @"
    if len(address) > 254 or len(local) > 64:
        return "Address is too long"
    if not LOCAL_RE.match(local) or local.startswith(".") or local.endswith(".") or ".." in local:
        return "The part before the @ has invalid characters or dots"
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return "Domain name is not valid"
    labels = domain.split(".")
    if len(labels) < 2 or not all(LABEL_RE.match(l) for l in labels):
        return "Domain name is not valid"
    if not (labels[-1].isalpha() or labels[-1].startswith("xn--")) or len(labels[-1]) < 2:
        return "Domain ending is not valid"
    return None


def lookup_mail_hosts(domain):
    """Return (hosts, error_status, reason). hosts is an ordered list or None."""
    domain = domain.encode("idna").decode("ascii")
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    try:
        answers = resolver.resolve(domain, "MX")
        records = sorted((r.preference, str(r.exchange).rstrip(".")) for r in answers)
        if len(records) == 1 and records[0][1] == "":
            return None, BOUNCE, "Domain publishes a null MX: it does not accept email"
        return [h for _, h in records], None, None
    except dns.resolver.NXDOMAIN:
        return None, BOUNCE, "Domain does not exist"
    except dns.resolver.NoAnswer:
        pass  # no MX; mail may go to the domain's own address
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return None, UNKNOWN, "DNS lookup failed or timed out"
    except dns.exception.DNSException:
        return None, UNKNOWN, "DNS lookup failed"
    for rtype in ("A", "AAAA"):
        try:
            resolver.resolve(domain, rtype)
            return [domain], None, None
        except dns.resolver.NXDOMAIN:
            return None, BOUNCE, "Domain does not exist"
        except dns.exception.DNSException:
            continue
    return None, BOUNCE, "Domain has no mail server"


_port25 = {"value": None}
_port25_lock = threading.Lock()


def smtp_available():
    """True if outbound port 25 works from here. Tested once, then cached."""
    mode = os.environ.get("SMTP_PROBE", "auto").lower()
    if mode == "off":
        return False
    if mode == "on":
        return True
    with _port25_lock:
        if _port25["value"] is None:
            ok = False
            for host in PORT25_TEST_HOSTS:
                try:
                    with socket.create_connection((host, 25), timeout=5):
                        ok = True
                        break
                except OSError:
                    continue
            _port25["value"] = ok
        return _port25["value"]


def _is_policy_refusal(text):
    text = text.lower()
    return any(w in text for w in POLICY_WORDS)


def _classify_rcpt(code, message):
    text = message.decode("utf-8", "replace") if isinstance(message, bytes) else str(message)
    if code in (250, 251):
        return DELIVERED, "Mail server accepted this mailbox"
    if 400 <= code < 500:
        return UNKNOWN, "Server asked to try again later (temporary reply or greylisting)"
    if code in (550, 551, 553) and not _is_policy_refusal(text):
        return BOUNCE, "Mail server says this mailbox does not exist"
    if code == 552:
        return UNKNOWN, "Mailbox exists but may be full"
    return UNKNOWN, "Server refused to answer for this mailbox"


def smtp_probe(hosts, address, catchall_cache):
    """Ask the mail server whether it would accept `address`. Sends no mail."""
    domain = address.rsplit("@", 1)[1].lower()
    last_error = "Could not connect to the domain's mail server"
    for host in hosts[:2]:
        server = smtplib.SMTP(local_hostname=HELO_HOST, timeout=SMTP_TIMEOUT)
        try:
            server.connect(host, 25)
            server.ehlo_or_helo_if_needed()
            code, _ = server.mail(MAIL_FROM)
            if code != 250:
                return UNKNOWN, "Server refused the probe before checking the mailbox"
            code, msg = server.rcpt(address)
            status, reason = _classify_rcpt(code, msg)
            if status == DELIVERED:
                if domain not in catchall_cache:
                    server.rset()
                    junk = "".join(random.choices(string.ascii_lowercase, k=16))
                    c2, _ = server.rcpt(f"zz-{junk}@{domain}")
                    catchall_cache[domain] = c2 in (250, 251)
                if catchall_cache[domain]:
                    return UNKNOWN, "Server accepts every address on this domain, so this one can't be confirmed"
            return status, reason
        except (smtplib.SMTPException, OSError) as exc:
            last_error = f"Mail server did not respond ({type(exc).__name__})"
        finally:
            try:
                server.quit()
            except Exception:
                server.close()
    return UNKNOWN, last_error


def check_group(addresses, probe_enabled):
    """Check addresses that share a domain, one at a time and politely."""
    out = []
    hosts_cache = {}
    catchall_cache = {}
    probed_before = False
    for address in addresses:
        err = check_syntax(address)
        if err:
            out.append(_result(address, BOUNCE, err))
            continue
        domain = address.rsplit("@", 1)[1].lower()
        if domain not in hosts_cache:
            hosts_cache[domain] = lookup_mail_hosts(domain)
        hosts, status, reason = hosts_cache[domain]
        if hosts is None:
            out.append(_result(address, status, reason))
            continue
        if not probe_enabled:
            out.append(_result(address, UNKNOWN,
                               "Domain can receive mail, but mailbox checks are off on this server"))
            continue
        if probed_before:
            time.sleep(DELAY_BETWEEN_PROBES)
        probed_before = True
        status, reason = smtp_probe(hosts, address, catchall_cache)
        out.append(_result(address, status, reason))
    return out


def _result(address, status, reason):
    return {"address": address, "status": status, "reason": reason}
