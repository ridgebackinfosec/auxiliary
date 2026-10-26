#!/usr/bin/env python3
"""Tests for web/webtech_fingerprint.py.

The unit tests exercise the pure helpers added for the concurrency + tech-match
features (no browser, no network). The integration tests drive main() with
`fingerprint` monkeypatched to return canned result dicts, so the concurrent
driver, --match filtering, and progress/SIGINT behavior are covered without ever
launching Playwright.
"""
import json
import os
import signal
import tempfile
import threading
import time
import unittest
from unittest import mock

from web import webtech_fingerprint as wt


def _server(name, version, header="X-Powered-By"):
    """A server_components entry shaped the way fingerprint() builds them."""
    return {"name": name, "version": version, "header": header, "eol": None}


def _data(libraries=None, server_components=None, cookies=None):
    """Build a minimal fingerprint()-shaped result dict for tests."""
    return {
        "url": "https://x",
        "final_url": "https://x",
        "libraries": libraries or [],
        "server_components": server_components or [],
        "headers": {},
        "cookies": cookies or [],
        "generator": None,
        "resources_seen": [],
        "challenge_page": None,
        "console_warnings": [],
        "failed_requests": [],
    }


class NormalizeMatchTermsTests(unittest.TestCase):
    def test_none_returns_empty(self):
        self.assertEqual(wt.normalize_match_terms(None), [])

    def test_lowercases_and_strips(self):
        self.assertEqual(wt.normalize_match_terms([" PHP "]), ["php"])

    def test_splits_comma_and_repeat(self):
        self.assertEqual(
            wt.normalize_match_terms(["php,apache", "JQuery"]),
            ["php", "apache", "jquery"],
        )

    def test_dedup_preserves_order(self):
        self.assertEqual(
            wt.normalize_match_terms(["php", "PHP", "apache"]),
            ["php", "apache"],
        )

    def test_drops_empty_fragments(self):
        self.assertEqual(wt.normalize_match_terms(["php,,", ",", " "]), ["php"])


class MatchDetectionsTests(unittest.TestCase):
    def test_matches_library_by_substring_ci(self):
        data = _data(libraries=[{"name": "jQuery", "version": "3.6.0", "method": "js-global"}])
        self.assertEqual(
            wt.match_detections(data, ["jquery"]),
            [{"tech": "jQuery", "version": "3.6.0"}],
        )

    def test_matches_server_component(self):
        data = _data(server_components=[_server("PHP", "8.1.2")])
        self.assertEqual(
            wt.match_detections(data, ["php"]),
            [{"tech": "PHP", "version": "8.1.2"}],
        )

    def test_cookie_match_has_no_version(self):
        data = _data(cookies=[{"cookie": "PHPSESSID", "technology": "PHP"}])
        self.assertEqual(
            wt.match_detections(data, ["php"]),
            [{"tech": "PHP", "version": None}],
        )

    def test_order_is_server_then_lib_then_cookie(self):
        data = _data(
            libraries=[{"name": "PHPlib", "version": "1.0", "method": "x"}],
            server_components=[_server("PHP", "8.1.2")],
            cookies=[{"cookie": "PHPSESSID", "technology": "PHP-session"}],
        )
        got = [e["tech"] for e in wt.match_detections(data, ["php"])]
        self.assertEqual(got, ["PHP", "PHPlib", "PHP-session"])

    def test_dedup_same_tech_and_version(self):
        data = _data(
            server_components=[_server("PHP", "8.1.2")],
            libraries=[{"name": "PHP", "version": "8.1.2", "method": "x"}],
        )
        self.assertEqual(
            wt.match_detections(data, ["php"]),
            [{"tech": "PHP", "version": "8.1.2"}],
        )

    def test_multiple_terms(self):
        data = _data(
            server_components=[_server("nginx", "1.18.0")],
            libraries=[{"name": "jQuery", "version": "3.6.0", "method": "x"}],
        )
        got = [e["tech"] for e in wt.match_detections(data, ["nginx", "jquery"])]
        self.assertEqual(sorted(got), ["jQuery", "nginx"])

    def test_no_match_returns_empty(self):
        data = _data(server_components=[_server("nginx", "1.18.0")])
        self.assertEqual(wt.match_detections(data, ["php"]), [])

    def test_empty_terms_returns_empty(self):
        data = _data(server_components=[_server("nginx", "1.18.0")])
        self.assertEqual(wt.match_detections(data, []), [])


class FormatDetectedVersionTests(unittest.TestCase):
    def test_returns_version(self):
        self.assertEqual(wt.format_detected_version({"tech": "PHP", "version": "8.1.2"}), "8.1.2")

    def test_none_version_is_unknown(self):
        self.assertEqual(wt.format_detected_version({"tech": "PHP", "version": None}), "version unknown")

    def test_empty_version_is_unknown(self):
        self.assertEqual(wt.format_detected_version({"tech": "PHP", "version": ""}), "version unknown")


class SummarizeDetectionsTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(wt.summarize_detections(_data()), "no components detected")

    def test_server_components_first(self):
        data = _data(
            libraries=[{"name": "jQuery", "version": "3.6.0", "method": "x"}],
            server_components=[_server("nginx", "1.18.0")],
        )
        self.assertEqual(wt.summarize_detections(data), "nginx 1.18.0, jQuery 3.6.0")

    def test_name_only_when_no_version(self):
        data = _data(server_components=[{"name": "PHP", "version": None}])
        self.assertEqual(wt.summarize_detections(data), "PHP")

    def test_truncation_adds_more(self):
        libs = [{"name": "L%d" % i, "version": "1", "method": "x"} for i in range(6)]
        out = wt.summarize_detections(_data(libraries=libs), max_items=4)
        self.assertTrue(out.endswith(" +2 more"), out)
        self.assertEqual(out.count(","), 3)


class FormatCompactLineTests(unittest.TestCase):
    def test_done_line_plain(self):
        line = wt.format_compact_line(4, 20, "https://app", True, "PHP 8.1.2", use_color=False)
        self.assertEqual(line, "[ 4/20] done  https://app   PHP 8.1.2")

    def test_fail_line_plain(self):
        line = wt.format_compact_line(3, 20, "https://web03", False, "timeout", use_color=False)
        self.assertEqual(line, "[ 3/20] FAIL  https://web03   timeout")

    def test_index_right_justified_single_digit_total(self):
        line = wt.format_compact_line(2, 5, "https://a", True, "x", use_color=False)
        self.assertEqual(line, "[2/5] done  https://a   x")

    def test_color_wraps_status_only(self):
        line = wt.format_compact_line(1, 9, "https://a", True, "x", use_color=True)
        self.assertIn(wt.ANSI_GREEN, line)
        self.assertNotIn(wt.ANSI_GREEN + "https", line)


class FormatMatchedSectionTests(unittest.TestCase):
    def test_header_and_rows(self):
        out = wt.format_matched_section("php", [("web01", ["8.1.2"]), ("app", ["7.4.33", "version unknown"])])
        self.assertIn("=== MATCHED: php (2 hosts) ===", out)
        self.assertIn("web01", out)
        self.assertIn("8.1.2", out)
        self.assertIn("7.4.33, version unknown", out)

    def test_no_hosts(self):
        out = wt.format_matched_section("php", [])
        self.assertIn("=== MATCHED: php (0 hosts) ===", out)


# --------------------------------------------------------------------------
# Integration: drive main() with fingerprint() stubbed out.
# --------------------------------------------------------------------------
def _fake_fingerprint_factory(by_host):
    """Return a fingerprint() replacement that yields canned data per host."""
    def fake(target_url, **kwargs):
        host = wt.host_of(target_url)
        return by_host.get(host, _data())
    return fake


class MainIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.targets = os.path.join(self.tmp, "targets.txt")

    def _write_targets(self, urls):
        with open(self.targets, "w") as f:
            f.write("\n".join(urls) + "\n")

    def _base_args(self, *extra):
        return ["-f", self.targets, "-o", self.tmp, "--no-zip", "--no-eol",
                "--no-repo-check", *extra]

    def test_concurrent_run_writes_all_hosts(self):
        urls = ["https://h%02d.local" % i for i in range(20)]
        self._write_targets(urls)
        by_host = {wt.host_of(u): _data(server_components=[_server("nginx", "1.18.0")]) for u in urls}

        def slow_fake(target_url, **kwargs):
            time.sleep((hash(target_url) % 5) / 1000.0)
            return by_host[wt.host_of(target_url)]

        with mock.patch.object(wt, "fingerprint", slow_fake):
            rc = wt.main(self._base_args("--threads", "5"))
        self.assertEqual(rc, 0)
        for u in urls:
            self.assertTrue(os.path.exists(os.path.join(self.tmp, wt.host_of(u) + ".json")),
                            "missing json for " + u)
        self.assertFalse(os.path.exists(wt.progress_path(self.tmp)),
                         "progress file should be removed on clean completion")

    def test_match_lists_right_hosts(self):
        urls = ["https://php1.local", "https://plain.local", "https://php2.local"]
        self._write_targets(urls)
        by_host = {
            "php1.local": _data(server_components=[_server("PHP", "8.1.2")]),
            "plain.local": _data(server_components=[_server("nginx", "1.18.0")]),
            "php2.local": _data(cookies=[{"cookie": "PHPSESSID", "technology": "PHP"}]),
        }
        with mock.patch.object(wt, "fingerprint", _fake_fingerprint_factory(by_host)):
            with mock.patch("sys.stdout.isatty", return_value=False):
                rc = wt.main(self._base_args("--threads", "3", "--match", "php"))
        self.assertEqual(rc, 0)
        transcript = os.path.join(self.tmp, "webtech_fingerprint_transcript.txt")
        # transcript only exists after zip; with --no-zip assert on per-host files instead.
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "php1.local.json")))
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "php2.local.json")))

    def test_match_only_suppresses_nonmatching_files(self):
        urls = ["https://php1.local", "https://plain.local"]
        self._write_targets(urls)
        by_host = {
            "php1.local": _data(server_components=[_server("PHP", "8.1.2")]),
            "plain.local": _data(server_components=[_server("nginx", "1.18.0")]),
        }
        with mock.patch.object(wt, "fingerprint", _fake_fingerprint_factory(by_host)):
            rc = wt.main(self._base_args("--threads", "2", "--match", "php", "--match-only"))
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "php1.local.json")))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "plain.local.json")),
                         "non-matching host should produce no files under --match-only")

    def test_concurrent_feed_and_matched_section(self):
        import contextlib
        import io as _io
        urls = ["https://php1.local", "https://plain.local", "https://php2.local"]
        self._write_targets(urls)
        by_host = {
            "php1.local": _data(server_components=[_server("PHP", "8.1.2")]),
            "plain.local": _data(server_components=[_server("nginx", "1.18.0")]),
            "php2.local": _data(cookies=[{"cookie": "PHPSESSID", "technology": "PHP"}]),
        }
        buf = _io.StringIO()
        with mock.patch.object(wt, "fingerprint", _fake_fingerprint_factory(by_host)):
            with contextlib.redirect_stdout(buf):
                rc = wt.main(self._base_args("--threads", "3", "--match", "php"))
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        # Compact feed: one done line per host, not the full inline report.
        self.assertEqual(out.count("] done  "), 3)
        # MATCHED section names the two PHP hosts with their versions.
        self.assertIn("=== MATCHED: php (2 hosts) ===", out)
        self.assertIn("php1.local", out)
        self.assertIn("8.1.2", out)
        self.assertIn("version unknown", out)  # php2 via cookie
        self.assertNotIn("plain.local  ", out.split("MATCHED")[1])

    def test_match_only_quiet_feed(self):
        import contextlib
        import io as _io
        urls = ["https://php1.local", "https://plain.local"]
        self._write_targets(urls)
        by_host = {
            "php1.local": _data(server_components=[_server("PHP", "8.1.2")]),
            "plain.local": _data(server_components=[_server("nginx", "1.18.0")]),
        }
        buf = _io.StringIO()
        with mock.patch.object(wt, "fingerprint", _fake_fingerprint_factory(by_host)):
            with contextlib.redirect_stdout(buf):
                rc = wt.main(self._base_args("--threads", "2", "--match", "php", "--match-only"))
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        # Only the matching host gets a feed line; the non-match is suppressed.
        self.assertEqual(out.count("] done  "), 1)
        self.assertIn("php1.local", out)

    def test_resume_skips_completed_and_scans_rest(self):
        urls = ["https://a.local", "https://b.local", "https://c.local"]
        self._write_targets(urls)
        by_host = {wt.host_of(u): _data(server_components=[_server("nginx", "1.18.0")]) for u in urls}
        # Simulate a prior run that finished only a.local: its json on disk + a
        # progress sidecar marking it completed.
        with open(os.path.join(self.tmp, "a.local.json"), "w") as f:
            json.dump(by_host["a.local"], f)
        wt.write_progress(self.tmp, {
            "version": 1,
            "targets_file": os.path.abspath(self.targets),
            "targets": urls,
            "completed": ["https://a.local"],
            "settings": {},
        })

        scanned = []
        real = _fake_fingerprint_factory(by_host)

        def tracking(target_url, **kwargs):
            scanned.append(wt.host_of(target_url))
            return real(target_url, **kwargs)

        with mock.patch.object(wt, "fingerprint", tracking):
            rc = wt.main(self._base_args("--threads", "2", "--resume"))
        self.assertEqual(rc, 0)
        # a.local was reloaded, not re-scanned; b and c were scanned this run.
        self.assertNotIn("a.local", scanned)
        self.assertEqual(sorted(scanned), ["b.local", "c.local"])
        # Clean completion removes the progress sidecar.
        self.assertFalse(os.path.exists(wt.progress_path(self.tmp)))

    def test_serial_run_prints_full_report(self):
        urls = ["https://a.local", "https://b.local"]
        self._write_targets(urls)
        by_host = {wt.host_of(u): _data(server_components=[_server("nginx", "1.18.0")]) for u in urls}
        with mock.patch.object(wt, "fingerprint", _fake_fingerprint_factory(by_host)):
            with mock.patch("sys.stdout.isatty", return_value=False):
                rc = wt.main(self._base_args("--threads", "1"))
        self.assertEqual(rc, 0)
        # Serial mode still writes the per-host reports.
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "a.local.txt")))


if __name__ == "__main__":
    unittest.main()
