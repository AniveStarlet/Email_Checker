import unittest
from unittest import mock

import checker
from app import app, parse_addresses


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
        self.assertEqual(c(550, b"5.7.1 blocked by spam policy")[0], checker.UNKNOWN)
        self.assertEqual(c(451, b"greylisted")[0], checker.UNKNOWN)
        self.assertEqual(c(554, b"no")[0], checker.UNKNOWN)


class Group(unittest.TestCase):
    def test_dns_only_mode(self):
        with mock.patch("checker.lookup_mail_hosts", return_value=(["mx.x.com"], None, None)):
            r = checker.check_group(["a@x.com", "bad"], probe_enabled=False)
        self.assertEqual([x["status"] for x in r], [checker.UNKNOWN, checker.BOUNCE])

    def test_missing_domain(self):
        with mock.patch("checker.lookup_mail_hosts", return_value=(None, checker.BOUNCE, "Domain does not exist")):
            r = checker.check_group(["a@nope.invalid"], probe_enabled=True)
        self.assertEqual(r[0]["status"], checker.BOUNCE)

    def test_catch_all_is_unknown(self):
        with mock.patch("checker.lookup_mail_hosts", return_value=(["mx.x.com"], None, None)), \
             mock.patch("checker.smtplib.SMTP") as smtp:
            s = smtp.return_value
            s.mail.return_value = (250, b"ok")
            s.rcpt.return_value = (250, b"ok")
            r = checker.check_group(["a@x.com"], probe_enabled=True)
        self.assertEqual(r[0]["status"], checker.UNKNOWN)
        self.assertIn("every address", r[0]["reason"])


class Web(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_addresses("a@x.com, B@y.com;a@x.com\n<c@z.com>"), ["a@x.com", "B@y.com", "c@z.com"])

    def test_endpoint(self):
        with mock.patch("checker.smtp_available", return_value=False):
            res = app.test_client().post("/check", json={"text": "nodomain\n"})
        self.assertEqual(res.get_json()["results"][0]["status"], "bounce")
        self.assertEqual(app.test_client().post("/check", json={"text": ""}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
