#!/usr/bin/env python3
"""Connect to your own local honeypot and send harmless test commands."""
import argparse
import socket
import sys
import time
import paramiko


def main():
    parser = argparse.ArgumentParser(description="Local SSH honeypot test client")
    parser.add_argument("host", nargs="?", default="127.0.0.1")
    parser.add_argument("port", nargs="?", type=int, default=2222)
    parser.add_argument("--username", default="testuser")
    parser.add_argument("--password", default="test-password")
    args = parser.parse_args()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(args.host, port=args.port, username=args.username,
                       password=args.password, look_for_keys=False,
                       allow_agent=False, timeout=5, banner_timeout=5,
                       auth_timeout=5)
        channel = client.invoke_shell()
        time.sleep(0.5)
        if channel.recv_ready():
            print(channel.recv(4096).decode("utf-8", errors="replace"), end="")
        for command in ("whoami", "id", "uname -a", "exit"):
            channel.send(command + "\n")
            time.sleep(0.3)
            while channel.recv_ready():
                print(channel.recv(4096).decode("utf-8", errors="replace"), end="")
        channel.close()
    except (paramiko.SSHException, OSError, socket.timeout) as exc:
        print(f"Connection/test failed: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        client.close()


if __name__ == "__main__":
    main()
