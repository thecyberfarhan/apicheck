import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from apicheck import checks, cli


class Vuln(BaseHTTPRequestHandler):
    """A deliberately weak local server used only for tests."""
    server_version = "Vuln/2.3"
    sys_version = ""

    def _send(self, code=200, body=b"", extra=()):
        self.send_response(code)
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        origin = self.headers.get("Origin")
        cors = [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")] if origin else []
        if self.path == "/":
            self._send(200, b"<html>home</html>", cors + [("Set-Cookie", "sessionid=abc; Path=/")])
        elif self.path == "/.git/HEAD":
            self._send(200, b"ref: refs/heads/main\n")
        elif self.path == "/api/users":
            self._send(200, b'[{"id":1,"email":"a@b.c"}]')
        elif self.path == "/openapi.json":
            self._send(200, json.dumps({"paths": {"/api/users": {"get": {}}}}).encode())
        elif self.path.startswith("/%27"):
            self._send(500, b"Traceback (most recent call last): boom")
        elif self.path == "/uploads/":
            self._send(200, b"<title>Index of /uploads</title>Index of /uploads/")
        else:
            self._send(404, b"nope")

    def do_OPTIONS(self):
        self._send(200, b"", [("Allow", "GET, PUT, DELETE")])

    def log_message(self, *a):
        pass


class Safe(Vuln):
    server_version = "Safe"
    def do_GET(self):
        self._send(200, b"ok", [("Content-Security-Policy", "default-src 'self'"), ("X-Content-Type-Options", "nosniff"),
                                ("X-Frame-Options", "DENY"), ("Referrer-Policy", "no-referrer")])

    def do_OPTIONS(self):
        self._send(200, b"", [("Allow", "GET")])


def serve(handler):
    s = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s, f"http://127.0.0.1:{s.server_address[1]}"


class ChecksTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vs, cls.vurl = serve(Vuln)
        cls.ss, cls.surl = serve(Safe)

    @classmethod
    def tearDownClass(cls):
        cls.vs.shutdown()
        cls.ss.shutdown()

    def titles(self, fn, url=None, *a):
        return [f.title for f in fn(checks.Target(url or self.vurl), *a)]

    def test_headers(self):
        t = self.titles(checks.check_headers)
        self.assertIn("Content-Security-Policy missing", t)
        self.assertIn("Version disclosed in header", t)

    def test_cookies(self):
        self.assertTrue(any("sessionid" in x for x in self.titles(checks.check_cookies)))

    def test_cors_reflection(self):
        f = checks.check_cors(checks.Target(self.vurl))
        self.assertEqual(f[0].severity, "high")

    def test_methods(self):
        self.assertIn("Write methods advertised", self.titles(checks.check_methods))

    def test_sensitive(self):
        self.assertIn("Git repository exposed", self.titles(checks.check_sensitive))

    def test_listing(self):
        self.assertIn("Directory listing enabled", self.titles(checks.check_listing))

    def test_errors(self):
        self.assertTrue(any("Verbose error" in x for x in self.titles(checks.check_errors)))

    def test_auth_with_token_compare(self):
        t = checks.Target(self.vurl, token="x")
        f = checks.check_auth(t, ["/api/users"])
        self.assertEqual(f[0].severity, "high")

    def test_openapi_discovery(self):
        self.assertEqual(checks.endpoints_from_openapi(checks.Target(self.vurl)), ["/api/users"])

    def test_safe_server_has_no_findings(self):
        t = checks.Target(self.surl)
        out = []
        for fn in checks.ALL_CHECKS:
            out += fn(t)
        self.assertEqual([f.title for f in out], [])

    def test_soft_404_does_not_create_false_positives(self):
        # Safe answers 200 to every path with the same body; sensitive-file check must stay quiet.
        self.assertEqual(checks.check_sensitive(checks.Target(self.surl)), [])

    def test_cli_json_report(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "r.json"
            self.assertEqual(cli.run([self.vurl, "-o", str(out)]), 0)
            data = json.loads(out.read_text())
            self.assertGreater(len(data["findings"]), 5)
            self.assertEqual(data["findings"][0]["severity"], "high")

    def test_cli_blocks_public(self):
        with self.assertRaises(SystemExit):
            cli.run(["http://8.8.8.8"])


if __name__ == "__main__":
    unittest.main()
