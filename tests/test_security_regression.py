"""HTTP regression checks for the four repaired DVWA Low-level modules."""

import os
import re
import sys
import unittest
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener


class Page(HTMLParser):
    def __init__(self, status, body):
        super().__init__(convert_charrefs=True)
        self.status = status
        self.body = body
        self.inputs = {}
        self.parts = []
        self.feed(body)
        self.close()
        self.text = " ".join(" ".join(self.parts).split())

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("name"):
            self.inputs[attrs["name"]] = attrs.get("value", "")

    def handle_data(self, data):
        self.parts.append(data)

    def token(self):
        token = self.inputs.get("user_token")
        if not token:
            raise RuntimeError("Missing CSRF token. Check the DVWA login/setup page.")
        return token


class Client:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.opener = build_opener(
            ProxyHandler({}), HTTPCookieProcessor(CookieJar())
        )

    def request(self, path, query=None, form=None):
        url = self.base_url + "/" + path.lstrip("/")
        if query is not None:
            url += "?" + urlencode(query)
        data = None if form is None else urlencode(form).encode("utf-8")
        request = Request(url, data=data, headers={"User-Agent": "IE3142-lab-tests"})
        try:
            response = self.opener.open(request, timeout=20)
        except HTTPError as error:
            response = error  # A rejected request can legitimately return HTTP 400.
        with response:
            return Page(response.getcode(), response.read().decode("utf-8", "replace"))


class SecurityRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        username = os.environ.get("DVWA_USERNAME")
        password = os.environ.get("DVWA_PASSWORD")
        if not username or not password:
            raise RuntimeError("Set DVWA_USERNAME and DVWA_PASSWORD for the lab account.")

        base_url = os.environ.get("DVWA_BASE_URL", "http://127.0.0.1:4280")
        cls.client = Client(base_url)
        login = cls.client.request("login.php")
        logged_in = cls.client.request("login.php", form={
            "username": username,
            "password": password,
            "Login": "Login",
            "user_token": login.token(),
        })
        if logged_in.status != 200 or "logout.php" not in logged_in.body:
            raise RuntimeError("DVWA login failed. Check the account and database setup.")

        security = cls.client.request("security.php")
        security = cls.client.request("security.php", form={
            "security": "low",
            "seclev_submit": "Submit",
            "user_token": security.token(),
        })
        cls.low_pattern = r"Security Level:\s*(?:Security Level:\s*)?low\b"
        if security.status != 200 or not re.search(cls.low_pattern, security.text):
            raise RuntimeError("Could not confirm Low security for the test session.")
        if not re.search(r"SQLi DB:\s*mysql\b", security.text):
            raise RuntimeError("These tests require the configured MySQL SQLi backend.")
        print(f"\nTarget: {base_url}; Python: {sys.version.split()[0]}", flush=True)
        print("Login verified; security=low; SQLi backend=mysql.\n", flush=True)

    def fetch(self, path, query=None, form=None, status=200):
        page = self.client.request(path, query=query, form=form)
        method = "POST" if form is not None else "GET"
        values = form if form is not None else query
        print(f"\n  {method} {path} input={values!r} -> HTTP {page.status}", flush=True)
        self.assertEqual(page.status, status, "Unexpected HTTP response status")
        self.assertIn("logout.php", page.body, "Response is not an authenticated DVWA page")
        self.assertRegex(page.text, self.low_pattern, "Security level changed")
        return page

    def sql(self, value, key="id"):
        return self.fetch("vulnerabilities/sqli/", query={key: value, "Submit": "Submit"})

    def test_01_sql_normal_user(self):
        page = self.sql("1")
        self.assertIn("First name: admin", page.text)
        self.assertIn("Surname: admin", page.text)
        self.assertEqual(page.text.count("First name:"), 1)

    def test_02_sql_second_user(self):
        page = self.sql("2")
        self.assertIn("First name: Gordon", page.text)
        self.assertIn("Surname: Brown", page.text)
        self.assertEqual(page.text.count("First name:"), 1)

    def test_03_sql_missing_user(self):
        page = self.sql("9999")
        self.assertIn("User not found.", page.text)
        self.assertNotIn("First name:", page.text)

    def test_04_sql_original_payload_rejected(self):
        page = self.sql("1' OR '1'='1")
        self.assertIn("Invalid user ID. Enter a positive whole number.", page.text)
        self.assertNotIn("First name:", page.text)

    def test_05_sql_array_rejected(self):
        page = self.sql("1", key="id[]")
        self.assertIn("Invalid user ID. Enter a positive whole number.", page.text)

    def test_06_xss_normal_name(self):
        page = self.fetch("vulnerabilities/xss_r/", query={"name": "Student"})
        self.assertIn("Hello Student", page.text)

    def test_07_xss_original_payload_encoded(self):
        payload = "<script>alert('IE3142-XSS')</script>"
        page = self.fetch("vulnerabilities/xss_r/", query={"name": payload})
        self.assertIn("Hello " + payload, page.text)
        self.assertIn("&lt;script&gt;", page.body)
        self.assertNotIn(payload, page.body)

    def test_08_xss_array_rejected(self):
        page = self.fetch("vulnerabilities/xss_r/", query={"name[]": "Student"})
        self.assertIn("Invalid name.", page.text)

    def test_09_command_normal_ping(self):
        page = self.fetch("vulnerabilities/exec/", form={
            "ip": "127.0.0.1", "Submit": "Submit",
        })
        self.assertIn("PING 127.0.0.1", page.text)
        self.assertRegex(page.text, r"4 packets transmitted,\s*4 (?:packets )?received")

    def test_10_command_original_payload_rejected(self):
        page = self.fetch("vulnerabilities/exec/", form={
            "ip": "127.0.0.1; echo IE3142-CMD", "Submit": "Submit",
        })
        self.assertIn("Invalid IP address.", page.text)
        self.assertNotIn("IE3142-CMD", page.text)
        self.assertNotIn("PING 127.0.0.1", page.text)

    def test_11_command_array_rejected(self):
        page = self.fetch("vulnerabilities/exec/", form={
            "ip[]": "127.0.0.1", "Submit": "Submit",
        })
        self.assertIn("Invalid IP address.", page.text)

    def test_12_file_inclusion_normal_pages(self):
        menu = self.fetch("vulnerabilities/fi/")
        self.assertIn("file1.php", menu.body)
        for number in (1, 2, 3):
            with self.subTest(page=f"file{number}.php"):
                page = self.fetch("vulnerabilities/fi/", query={
                    "page": f"file{number}.php",
                })
                heading = rf"<h[1-6]\b[^>]*>\s*File {number}\s*</h[1-6]>"
                self.assertRegex(page.body, heading)

    def test_13_file_inclusion_original_payload_rejected(self):
        page = self.fetch("vulnerabilities/fi/", query={
            "page": "../../../../../etc/os-release",
        }, status=400)
        self.assertIn("Invalid page selection.", page.text)
        self.assertNotIn("PRETTY_NAME=", page.body)

    def test_14_file_inclusion_array_rejected(self):
        page = self.fetch("vulnerabilities/fi/", query={
            "page[]": "file1.php",
        }, status=400)
        self.assertIn("Invalid page selection.", page.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)