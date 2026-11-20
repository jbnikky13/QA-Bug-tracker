import unittest
from unittest.mock import patch
from scanner import scan_url, run_scan, _check_links
from security_boundary import UnsafeTarget


class ScannerBoundaryTests(unittest.TestCase):
    def test_scan_url_rejects_loopback_before_network(self):
        with self.assertRaises(UnsafeTarget):
            scan_url("http://127.0.0.1")

    def test_run_scan_rejects_private_target_before_network(self):
        with self.assertRaises(UnsafeTarget):
            run_scan("http://192.168.1.10")

    def test_link_checker_skips_private_destinations(self):
        html = '<a href="http://127.0.0.1/admin">admin</a><a href="https://example.com/path">public</a>'
        def validate(url):
            if "127.0.0.1" in url:
                raise UnsafeTarget("blocked")
            return url
        with patch("scanner.validate_url", side_effect=validate), patch("scanner.safe_request") as request:
            request.return_value.status_code = 200
            _check_links(html, "https://example.com", check_external=True)
            requested = [call.args[0] for call in request.call_args_list]
            self.assertNotIn("http://127.0.0.1/admin", requested)


if __name__ == "__main__":
    unittest.main()
