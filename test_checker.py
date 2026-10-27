import json
import smtplib
import unittest
from types import SimpleNamespace
from unittest import mock

import dns.exception
import dns.resolver

import checker
from app import app, parse_addresses

checker.DELAY_BETWEEN_PROBES = 0


def fake_server(mail=(250, b"ok"), rcpt=(250, b"ok"), rcpt_side_effect=None):
    s = mock.MagicMock()
    s.mail.return_value = mail
    s.rcpt.return_value = rcpt
    if rcpt_side_effect is not None:
        s.rcpt.side_effect = rcpt_side_effect
    return s


class Syntax(unittest.TestCase):
    def test_valid(self):
        self.assertIsNone(checker.check_syntax("a.b+tag@example.com"))

    def test_invalid(self):
        for bad in ["plain", "a@@b.com", "@x.com", "a@", "a..b@x.com", ".a@x.com", "a@x", "a@-x.com", "a b@x.com", "a@x.c0m"]:
            self.assertIsNotNone(checker.check_syntax(bad), bad)


class Classify(unittest.TestCase):
    def test_codes(self):
        c = checker._classify_rcpt
        self.assertEqual(c(250, b"OK")[0], checker.DELIVERED)
        self.assertEqual(c(550, b"5.1.1 User unknown")[0], checker.BOUNCE)
        self.assertEqual(c(553, b"5.1.3 bad mailbox")[0], checker.BOUNCE)
        self.assertEqual(c(550, b"5.7.1 blocked by spam policy")[0], checker.UNKNOWN)
        self.assertEqual(c(550, b"Relay access denied")[0], checker.UNKNOWN)
        self.assertEqual(c(554, b"no")[0], checker.UNKNOWN)
        self.assertEqual(c(552, b"mailbox full")[0], checker.UNKNOWN)

    def test_temporary_flag(self):
        for code in (421, 450, 451, 452):
            status, _, temp = checker._classify_rcpt(code, b"try later")
            self.assertEqual((status, temp), (checker.UNKNOWN, True), code)
        self.assertFalse(checker._classify_rcpt(550, b"user unknown")[2])


class Dns(unittest.TestCase):
    def lookup(self, side_effect):
        with mock.patch("checker.dns.resolver.Resolver") as R:
            R.return_value.resolve.side_effect = side_effect
            return checker.lookup_mail_hosts("example.com")

    def test_mx_sorted_by_preference(self):
        recs = [SimpleNamespace(preference=20, exchange="b.x.com."), SimpleNamespace(preference=10, exchange="a.x.com.")]
        self.assertEqual(self.lookup([recs])[0], ["a.x.com", "b.x.com"])

    def test_nxdomain(self):
        self.assertEqual(self.lookup(dns.resolver.NXDOMAIN())[1], checker.BOUNCE)

    def test_null_mx(self):
        self.assertEqual(self.lookup([[SimpleNamespace(preference=0, exchange=".")]])[1], checker.BOUNCE)

    def test_falls_back_to_a_record(self):
        hosts, status, _ = self.lookup([dns.resolver.NoAnswer(), ["1.2.3.4"]])
        self.assertEqual(hosts, ["example.com"])

    def test_no_mx_and_no_address(self):
        self.assertEqual(self.lookup(dns.resolver.NoAnswer())[1], checker.BOUNCE)

    def test_timeout_is_unknown_not_bounce(self):
        self.assertEqual(self.lookup(dns.exception.Timeout())[1], checker.UNKNOWN)


class Probe(unittest.TestCase):
    def probe(self, servers, cache=None):
        with mock.patch("checker.smtplib.SMTP", side_effect=servers):
            return checker.smtp_probe(["mx1.x.com", "mx2.x.com"], "a@x.com", {} if cache is None else cache)

    def test_never_sends_message_content(self):
        s = fake_server()
        self.probe([s])
        self.assertFalse(s.data.called)
        self.assertFalse(s.sendmail.called)
        self.assertFalse(s.send_message.called)

    def test_falls_back_to_second_mx(self):
        bad = fake_server(); bad.connect.side_effect = OSError("refused")
        good = fake_server(rcpt_side_effect=[(250, b"ok"), (550, b"5.1.1 unknown")])
        self.assertEqual(self.probe([bad, good])[0], checker.DELIVERED)

    def test_mailbox_missing_is_bounce(self):
        self.assertEqual(self.probe([fake_server(rcpt=(550, b"5.1.1 User unknown"))])[0], checker.BOUNCE)

    def test_sender_refused_is_unknown(self):
        status, _, _ = self.probe([fake_server(mail=(530, b"auth required"))])
        self.assertEqual(status, checker.UNKNOWN)

    def test_greylisting_is_temporary(self):
        status, _, temp = self.probe([fake_server(rcpt=(451, b"4.7.1 greylisted"))])
        self.assertEqual((status, temp), (checker.UNKNOWN, True))

    def test_disconnect_mid_conversation(self):
        s = fake_server(rcpt_side_effect=smtplib.SMTPServerDisconnected("gone"))
        status, reason, temp = self.probe([s, fake_server(rcpt_side_effect=smtplib.SMTPServerDisconnected("gone"))])
        self.assertEqual((status, temp), (checker.UNKNOWN, True))
        self.assertIn("did not respond", reason)

    def test_all_hosts_unreachable(self):
        a, b = fake_server(), fake_server()
        a.connect.side_effect = b.connect.side_effect = TimeoutError()
        self.assertEqual(self.probe([a, b])[0], checker.UNKNOWN)

    def test_catch_all_detected(self):
        status, reason, _ = self.probe([fake_server()])
        self.assertEqual(status, checker.UNKNOWN)
        self.assertIn("every address", reason)

    def test_catch_all_result_is_cached_per_domain(self):
        s = fake_server(rcpt_side_effect=[(250, b"ok")])
        status, _, _ = self.probe([s], cache={"x.com": False})
        self.assertEqual(status, checker.DELIVERED)
        self.assertEqual(s.rcpt.call_count, 1)  # no second, made-up address probe


class Hints(unittest.TestCase):
    def test_typo_suggestions(self):
        self.assertEqual(checker.suggest_domain("gmial.com"), "gmail.com")
        self.assertEqual(checker.suggest_domain("hotmial.com"), "hotmail.com")
        self.assertIsNone(checker.suggest_domain("gmail.com"))
        self.assertIsNone(checker.suggest_domain("mail.com"))
        self.assertIsNone(checker.suggest_domain("example.org"))

    def test_notes(self):
        self.assertEqual(checker.domain_notes("sam@gmial.com"), ["Did you mean sam@gmail.com?"])
        self.assertIn("Disposable", checker.domain_notes("x@mailinator.com")[0])
        self.assertEqual(checker.domain_notes("x@example.org"), [])


class Group(unittest.TestCase):
    def test_dns_only_mode(self):
        with mock.patch("checker.lookup_mail_hosts", return_value=(["mx.x.com"], None, None)):
            r = checker.check_group(["a@x.com", "bad"], probe_enabled=False)
        self.assertEqual([x["status"] for x in r], [checker.UNKNOWN, checker.BOUNCE])
        self.assertFalse(r[0]["temporary"])

    def test_missing_domain(self):
        with mock.patch("checker.lookup_mail_hosts", return_value=(None, checker.BOUNCE, "Domain does not exist")):
            r = checker.check_group(["a@nope.invalid"], probe_enabled=True)
        self.assertEqual(r[0]["status"], checker.BOUNCE)

    def test_typo_note_attached(self):
        with mock.patch("checker.lookup_mail_hosts", return_value=(None, checker.BOUNCE, "Domain does not exist")):
            r = checker.check_group(["sam@gmial.com"], probe_enabled=True)
        self.assertEqual(r[0]["notes"], ["Did you mean sam@gmail.com?"])

    def test_one_failure_does_not_stop_the_rest(self):
        def boom(domain):
            if domain == "bad.com":
                raise RuntimeError("boom")
            return (["mx.x.com"], None, None)
        with mock.patch("checker.lookup_mail_hosts", side_effect=boom):
            r = checker.check_group(["a@bad.com", "b@good.com"], probe_enabled=False)
        self.assertIn("failed unexpectedly", r[0]["reason"])
        self.assertTrue(r[0]["temporary"])
        self.assertEqual(r[1]["status"], checker.UNKNOWN)

    def test_logs_domain_but_not_local_part(self):
        with mock.patch("checker.lookup_mail_hosts", return_value=(None, checker.BOUNCE, "Domain does not exist")):
            with self.assertLogs("checker", level="INFO") as cm:
                checker.check_group(["secret.person@nope.invalid"], probe_enabled=True)
        line = json.loads(cm.records[-1].getMessage())
        self.assertEqual((line["event"], line["domain"], line["status"]), ("address_checked", "nope.invalid", "bounce"))
        self.assertNotIn("secret", cm.records[-1].getMessage())


class PortDetection(unittest.TestCase):
    def setUp(self):
        checker._port25["value"] = None

    def tearDown(self):
        checker._port25["value"] = None

    def test_env_overrides(self):
        with mock.patch.dict("os.environ", {"SMTP_PROBE": "off"}):
            self.assertFalse(checker.smtp_available())
        with mock.patch.dict("os.environ", {"SMTP_PROBE": "on"}):
            self.assertTrue(checker.smtp_available())

    def test_blocked_port_detected_and_cached(self):
        with mock.patch.dict("os.environ", {"SMTP_PROBE": "auto"}), \
             mock.patch("checker.socket.create_connection", side_effect=OSError) as cc:
            self.assertFalse(checker.smtp_available())
            self.assertFalse(checker.smtp_available())
        self.assertEqual(cc.call_count, len(checker.PORT25_TEST_HOSTS))  # tested once, then cached


class Web(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        patcher = mock.patch("checker.smtp_available", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_parse(self):
        self.assertEqual(parse_addresses("a@x.com, B@y.com;a@x.com\n<c@z.com> mailto:d@w.com"),
                         ["a@x.com", "B@y.com", "c@z.com", "d@w.com"])

    def test_endpoint(self):
        res = self.client.post("/check", json={"text": "nodomain\n"})
        self.assertEqual(res.get_json()["results"][0]["status"], "bounce")
        self.assertEqual(self.client.post("/check", json={"text": ""}).status_code, 400)

    def test_too_many_addresses(self):
        text = "\n".join(f"u{i}@x.com" for i in range(51))
        self.assertEqual(self.client.post("/check", json={"text": text}).status_code, 400)

    def test_stream_sends_header_line_then_every_result(self):
        res = self.client.post("/check/stream", json={"text": "bad\nalso-bad"})
        lines = [json.loads(l) for l in res.get_data(as_text=True).splitlines()]
        self.assertEqual(lines[0], {"smtp": False, "addresses": ["bad", "also-bad"]})
        self.assertEqual(sorted(l["address"] for l in lines[1:]), ["also-bad", "bad"])
        self.assertEqual(res.mimetype, "application/x-ndjson")

    def test_favicon_and_health(self):
        self.assertEqual(self.client.get("/favicon.ico").status_code, 204)
        self.assertEqual(self.client.get("/health").get_json(), {"status": "ok"})

    def test_page_has_banner_when_smtp_off(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn("Mailbox checks are off", html)
        self.assertNotIn('id="banner" hidden', html)


if __name__ == "__main__":
    unittest.main()

