#!/usr/bin/env python3
"""
Minimal low-interaction SSH honeypot.

What it does:
  * Listens like an OpenSSH server and records every password login attempt.
  * After N failed attempts per connection it "lets the attacker in" to a FAKE shell.
  * Records every command typed. Nothing is ever executed and nothing is downloaded.
  * Writes structured events (JSON Lines) for later analysis with analyze.py.

Run it only on an isolated host or container. See README.md.
"""
import argparse
import json
import logging
import os
import socket
import threading
import time
from datetime import datetime, timezone

import paramiko

SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
HOSTNAME = "srv-web01"
LOG_LOCK = threading.Lock()
LOG_PATH = "logs/honeypot.jsonl"
IP_ATTEMPTS = {}  # source IP -> total password attempts seen (across connections)
ATTEMPT_LOCK = threading.Lock()


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
def log_event(event, **fields):
    """Append one JSON object per line. Thread-safe."""
    record = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
    with LOG_LOCK:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    logging.info("%s %s", event, fields)


# --------------------------------------------------------------------------- #
# Fake command responses (nothing is executed on the host)
# --------------------------------------------------------------------------- #
def fake_command(cmd, user):
    parts = cmd.strip().split()
    if not parts:
        return ""
    base = parts[0]
    home = "/root" if user == "root" else f"/home/{user}"
    if base == "whoami":
        return user
    if base == "id":
        if user == "root":
            return "uid=0(root) gid=0(root) groups=0(root)"
        return f"uid=1000({user}) gid=1000({user}) groups=1000({user})"
    if base == "pwd":
        return home
    if base == "uname":
        return "Linux srv-web01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
    if base == "ls":
        return "backup.tar.gz  notes.txt"
    if base == "cat" and len(parts) > 1 and parts[1] == "/etc/passwd":
        return ("root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin")
    if base in ("wget", "curl", "tftp", "ftp"):
        return ""  # pretend it worked; the URL is captured in the command log
    return f"-bash: {base}: command not found"


# --------------------------------------------------------------------------- #
# SSH server behaviour
# --------------------------------------------------------------------------- #
class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, ip, accept_after):
        self.ip = ip
        self.accept_after = accept_after
        self.attempts = 0
        self.username = None
        self.exec_command = None
        self.shell_requested = False
        self.channel_ready = threading.Event()

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self.attempts += 1
        with ATTEMPT_LOCK:
            IP_ATTEMPTS[self.ip] = IP_ATTEMPTS.get(self.ip, 0) + 1
            total = IP_ATTEMPTS[self.ip]
        log_event("auth_attempt", ip=self.ip, username=username,
                  password=password, attempt=total)
        if self.accept_after and total >= self.accept_after:
            self.username = username
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        log_event("pubkey_attempt", ip=self.ip, username=username,
                  fingerprint=key.get_fingerprint().hex())
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pw, ph, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.shell_requested = True
        self.channel_ready.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_command = command.decode("utf-8", errors="replace")
        log_event("exec_command", ip=self.ip, username=self.username,
                  command=self.exec_command)
        self.channel_ready.set()
        return True


def run_shell(chan, server, ip, args):
    """A fake interactive shell that only logs input."""
    user = server.username or "root"
    prompt = f"{user}@{HOSTNAME}:~$ "
    chan.send("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n")
    chan.send(prompt)
    chan.settimeout(1.0)

    buf, last, count, start = "", "", 0, time.time()
    while time.time() - start < args.session_timeout and count < args.max_commands:
        try:
            data = chan.recv(1024)
        except socket.timeout:
            continue
        if not data:
            break
        for ch in data.decode("utf-8", errors="replace"):
            if ch in "\r\n":
                if ch == "\n" and last == "\r":
                    last = ch
                    continue
                chan.send("\r\n")
                cmd, buf = buf.strip(), ""
                if cmd:
                    count += 1
                    log_event("command", ip=ip, username=user, command=cmd)
                    if cmd in ("exit", "logout"):
                        chan.send("logout\r\n")
                        return
                    out = fake_command(cmd, user)
                    if out:
                        chan.send(out.replace("\n", "\r\n") + "\r\n")
                chan.send(prompt)
            elif ch in ("\x7f", "\x08"):
                if buf:
                    buf = buf[:-1]
                    chan.send("\b \b")
            elif ch == "\x03":
                buf = ""
                chan.send("^C\r\n" + prompt)
            elif ch == "\x04":
                return
            elif ch.isprintable() and len(buf) < 1024:
                buf += ch
                chan.send(ch)
            last = ch


def handle_client(client, addr, host_key, args, sem):
    ip, port = addr[0], addr[1]
    started = time.time()
    transport = None
    try:
        client.settimeout(30)
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        transport.add_server_key(host_key)
        server = HoneypotServer(ip, args.accept_after)
        log_event("connection", ip=ip, port=port)

        transport.start_server(server=server)
        log_event("client_version", ip=ip, version=transport.remote_version)

        chan = transport.accept(30)
        if chan is None:
            return
        server.channel_ready.wait(10)

        if server.exec_command is not None:
            out = fake_command(server.exec_command, server.username or "root")
            if out:
                chan.send(out + "\n")
            chan.send_exit_status(0)
        elif server.shell_requested:
            run_shell(chan, server, ip, args)
        chan.close()
    except (paramiko.SSHException, EOFError, OSError) as exc:
        # Scanners disconnect mid-handshake constantly; this is normal noise.
        logging.debug("session error from %s: %s", ip, exc)
    finally:
        if transport:
            transport.close()
        client.close()
        sem.release()
        log_event("disconnect", ip=ip, duration=round(time.time() - started, 2))


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def load_host_key(path):
    if os.path.exists(path):
        return paramiko.RSAKey(filename=path)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    os.chmod(path, 0o600)
    return key


def main():
    global LOG_PATH
    p = argparse.ArgumentParser(description="Low-interaction SSH honeypot")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=2222)
    p.add_argument("--log-file", default="logs/honeypot.jsonl")
    p.add_argument("--host-key", default="host_key.pem")
    p.add_argument("--accept-after", type=int, default=3,
                   help="grant fake shell once a source IP has made N password attempts (0 = never)")
    p.add_argument("--max-connections", type=int, default=50)
    p.add_argument("--session-timeout", type=int, default=120)
    p.add_argument("--max-commands", type=int, default=50)
    args = p.parse_args()

    LOG_PATH = args.log_file
    os.makedirs(os.path.dirname(LOG_PATH) or ".", exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    host_key = load_host_key(args.host_key)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(100)
    sem = threading.BoundedSemaphore(args.max_connections)
    logging.info("Honeypot listening on %s:%d", args.host, args.port)

    try:
        while True:
            client, addr = sock.accept()
            if not sem.acquire(blocking=False):  # connection cap = basic DoS guard
                client.close()
                continue
            threading.Thread(target=handle_client,
                             args=(client, addr, host_key, args, sem),
                             daemon=True).start()
    except KeyboardInterrupt:
        logging.info("Shutting down")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
