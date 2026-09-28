#!/usr/bin/env python3
"""Unit tests for the pure pieces of pivot/reverse_ssh_tunnel.py.

These never shell out to a real ssh; only command-string builders, parsers,
validators, and the HMAC helpers are exercised.
"""
import unittest

from pivot import reverse_ssh_tunnel as rt

# A valid throwaway ed25519 public key (structurally real; not a live credential).
GOOD_KEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIGYmZhbOpjg0wH1vdlgUpl7uBioRznXlC2EuyLMWn1UA "
    "smoke-test"
)


class NormalizeTests(unittest.TestCase):
    def test_crlf_stripped(self):
        self.assertEqual(rt.normalize_pubkey_text("a b c\r\n"), "a b c\n")

    def test_lone_cr_stripped(self):
        self.assertEqual(rt.normalize_pubkey_text("a b\r"), "a b\n")

    def test_single_trailing_newline(self):
        self.assertEqual(rt.normalize_pubkey_text("a b\n\n\n"), "a b\n")

    def test_bytes_roundtrip(self):
        self.assertEqual(rt.normalize_pubkey_bytes(b"a b\r\n"), b"a b\n")


class PubkeyValidationTests(unittest.TestCase):
    def test_accepts_valid(self):
        self.assertTrue(rt.is_valid_pubkey(GOOD_KEY))
        self.assertTrue(rt.is_valid_pubkey(GOOD_KEY + "\n"))

    def test_rejects_garbage(self):
        self.assertFalse(rt.is_valid_pubkey("not-a-key"))

    def test_rejects_bad_base64(self):
        self.assertFalse(rt.is_valid_pubkey("ssh-ed25519 @@@notbase64@@@ x"))

    def test_rejects_multiline(self):
        self.assertFalse(rt.is_valid_pubkey(GOOD_KEY + "\n" + GOOD_KEY))

    def test_rejects_unknown_type(self):
        self.assertFalse(rt.is_valid_pubkey("ssh-magic AAAAB3 x"))

    def test_private_key_detected(self):
        self.assertTrue(rt.looks_like_private_key(
            "-----BEGIN OPENSSH PRIVATE KEY-----"))
        self.assertFalse(rt.looks_like_private_key(GOOD_KEY))


class HmacTests(unittest.TestCase):
    def test_roundtrip(self):
        mac = rt.compute_mac("s3cret", b"payload")
        self.assertTrue(rt.verify_mac("s3cret", b"payload", mac))

    def test_wrong_secret_fails(self):
        mac = rt.compute_mac("right", b"payload")
        self.assertFalse(rt.verify_mac("wrong", b"payload", mac))

    def test_tampered_payload_fails(self):
        mac = rt.compute_mac("s3cret", b"payload")
        self.assertFalse(rt.verify_mac("s3cret", b"payloaX", mac))


class VersionTests(unittest.TestCase):
    def test_parses_common_format(self):
        self.assertEqual(
            rt.parse_ssh_version("OpenSSH_9.6p1 Ubuntu-3ubuntu13, OpenSSL 3.0"),
            (9, 6))

    def test_parses_old(self):
        self.assertEqual(rt.parse_ssh_version("OpenSSH_7.4p1"), (7, 4))

    def test_none_on_junk(self):
        self.assertIsNone(rt.parse_ssh_version("no version here"))

    def test_at_least(self):
        self.assertTrue(rt.version_at_least((7, 6), 7, 6))
        self.assertTrue(rt.version_at_least((8, 0), 7, 6))
        self.assertFalse(rt.version_at_least((7, 4), 7, 6))
        self.assertFalse(rt.version_at_least(None, 7, 6))


class TunnelCommandTests(unittest.TestCase):
    def test_socks_default(self):
        cmd = rt.build_tunnel_command(host="h", user="u",
                                      identity="/k", socks_port=9050)
        self.assertEqual(cmd[0], "ssh")
        self.assertIn("-N", cmd)
        self.assertIn("127.0.0.1:9050", cmd)
        self.assertEqual(cmd[-1], "u@h")
        self.assertIn("IdentitiesOnly=yes", cmd)
        self.assertIn("ServerAliveInterval=30", cmd)

    def test_custom_socks_port(self):
        cmd = rt.build_tunnel_command(host="h", user="u", socks_port=1080)
        self.assertIn("127.0.0.1:1080", cmd)

    def test_forward_mode(self):
        cmd = rt.build_tunnel_command(host="h", user="u",
                                      forward="8022:localhost:3389")
        i = cmd.index("-R")
        self.assertEqual(cmd[i + 1], "8022:localhost:3389")

    def test_ssh_host_alias(self):
        cmd = rt.build_tunnel_command(ssh_host="redir")
        self.assertEqual(cmd[-1], "redir")

    def test_host_only_no_user(self):
        cmd = rt.build_tunnel_command(host="h")
        self.assertEqual(cmd[-1], "h")


class ConfigEntryTests(unittest.TestCase):
    def test_block(self):
        blk = rt.build_config_entry("redir", "h.example", "u", "/k", 9050)
        self.assertIn("Host redir", blk)
        self.assertIn("HostName h.example", blk)
        self.assertIn("User u", blk)
        self.assertIn("IdentityFile /k", blk)
        self.assertIn("IdentitiesOnly yes", blk)
        self.assertIn("RemoteForward 127.0.0.1:9050", blk)


class DiagramTests(unittest.TestCase):
    def test_flowchart(self):
        d = rt.build_diagram(sequence=False)
        self.assertIn("flowchart", d)
        for node in ("Operator host", "Remote redirector", "Internal sender"):
            self.assertIn(node, d)

    def test_sequence(self):
        d = rt.build_diagram(sequence=True)
        self.assertIn("sequenceDiagram", d)
        self.assertIn("keygen", d)


class ArgParseTests(unittest.TestCase):
    def test_tunnel_defaults(self):
        args = rt.build_parser().parse_args(
            ["tunnel", "--host", "h", "--user", "u"])
        self.assertEqual(args.socks_port, 9050)
        self.assertEqual(args.func, rt.cmd_tunnel)

    def test_send_key_defaults(self):
        args = rt.build_parser().parse_args(["send-key", "--host", "h"])
        self.assertEqual(args.port, 4444)
        self.assertEqual(args.func, rt.cmd_send_key)

    def test_diagram_sequence_flag(self):
        args = rt.build_parser().parse_args(["diagram", "--sequence"])
        self.assertTrue(args.sequence)
        self.assertEqual(args.func, rt.cmd_diagram)

    def test_verify_test_port_defaults_off_socks_port(self):
        # verify uses a throwaway port so it does not collide with a live tunnel.
        args = rt.build_parser().parse_args(["verify", "--host", "h", "--user", "u"])
        self.assertIsNone(args.test_port)
        resolved = args.test_port if args.test_port else args.socks_port + 10000
        self.assertEqual(resolved, 19050)
        self.assertNotEqual(resolved, args.socks_port)

    def test_verify_test_port_override(self):
        args = rt.build_parser().parse_args(
            ["verify", "--host", "h", "--test-port", "12345"])
        self.assertEqual(args.test_port, 12345)

    def test_tunnel_forward_accepted(self):
        args = rt.build_parser().parse_args(
            ["tunnel", "--host", "h", "--forward", "8022:localhost:3389"])
        self.assertEqual(args.forward, "8022:localhost:3389")

    def test_tunnel_socks_and_forward_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            rt.build_parser().parse_args(
                ["tunnel", "--host", "h", "--socks", "--forward", "8022:localhost:3389"])


if __name__ == "__main__":
    unittest.main()
