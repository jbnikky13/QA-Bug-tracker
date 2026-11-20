import unittest
from unittest.mock import patch, Mock

from security_boundary import UnsafeTarget, validate_url, safe_request


class BoundaryTests(unittest.TestCase):
    def test_allows_http_public_literal(self):
        self.assertEqual(validate_url("http://8.8.8.8"), "http://8.8.8.8/")

    def test_blocks_private_literal(self):
        for host in ("127.0.0.1", "10.0.0.1", "192.168.1.2", "169.254.169.254", "::1"):
            with self.subTest(host=host), self.assertRaises(UnsafeTarget):
                validate_url(f"http://[{host}]" if ":" in host else f"http://{host}")

    def test_blocks_non_http_scheme(self):
        with self.assertRaises(UnsafeTarget):
            validate_url("file:///etc/passwd")

    def test_blocks_url_credentials(self):
        with self.assertRaises(UnsafeTarget):
            validate_url("https://user:pass@example.com")

    def test_blocks_disallowed_port(self):
        with self.assertRaises(UnsafeTarget):
            validate_url("https://example.com:8443", resolve_dns=False)

    def test_blocks_local_names(self):
        for name in ("localhost", "foo.localhost", "host.local", "host.internal"):
            with self.subTest(name=name), self.assertRaises(UnsafeTarget):
                validate_url(f"http://{name}", resolve_dns=False)

    @patch("security_boundary.socket.getaddrinfo")
    def test_blocks_hostname_with_private_dns_answer(self, resolver):
        resolver.return_value = [
            (2, 1, 6, "", ("8.8.8.8", 80)),
            (2, 1, 6, "", ("192.168.0.2", 80)),
        ]
        with self.assertRaises(UnsafeTarget):
            validate_url("http://example.test")

    @patch("security_boundary.socket.getaddrinfo")
    def test_allows_hostname_with_public_dns_answers(self, resolver):
        resolver.return_value = [(2, 1, 6, "", ("8.8.8.8", 80))]
        self.assertTrue(validate_url("http://example.test").startswith("http://example.test"))

    def test_safe_request_does_not_follow_redirect_automatically(self):
        session = Mock()
        response = Mock(status_code=200, headers={}, url="")
        session.request.return_value = response
        safe_request("http://8.8.8.8", session=session)
        self.assertFalse(session.request.call_args.kwargs["allow_redirects"])

    def test_request_rejects_wrong_allowed_origin(self):
        session = Mock()
        with self.assertRaises(UnsafeTarget):
            safe_request("http://8.8.8.8", session=session, allowed_origin="https://worker.example")
        self.assertEqual(session.request.call_count, 0)

    def test_redirect_to_other_origin_is_blocked(self):
        session = Mock()
        first = Mock(status_code=302, headers={"Location": "http://9.9.9.9/"})
        session.request.return_value = first
        with self.assertRaises(UnsafeTarget):
            safe_request("http://8.8.8.8", session=session, allowed_origin="http://8.8.8.8")
        self.assertEqual(session.request.call_count, 1)

    def test_redirect_to_private_destination_is_blocked(self):
        session = Mock()
        first = Mock(status_code=302, headers={"Location": "http://127.0.0.1/"})
        session.request.return_value = first
        with self.assertRaises(UnsafeTarget):
            safe_request("http://8.8.8.8", session=session)
        self.assertEqual(session.request.call_count, 1)


if __name__ == "__main__":
    unittest.main()
