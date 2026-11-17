# SSH Honeypot

A low-interaction SSH honeypot built with Python and Paramiko. It imitates an SSH server, records authentication attempts and commands, and generates a Markdown activity report.

> **Safety:** This project records credentials that connecting clients attempt, including plaintext password values in its private JSONL log. Never use real credentials. Keep logs and SSH host keys private. Run only on a disposable VPS or isolated lab network that you own or are authorized to use. Do not expose this service from your personal/home network.

## Features

- SSH banner resembling OpenSSH
- Logs password and public-key authentication attempts
- Records client SSH versions, connections, and shell commands
- Fake shell with canned responses; attacker commands are never executed
- JSON Lines event logging
- Markdown activity report
- Docker deployment with a non-root user and container hardening

## Project structure

```text
ssh-honeypot/
├── honeypot.py
├── analyze.py
├── test_client.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .gitignore
└── README.md
```

## Run locally (Windows PowerShell)

1. Install Python 3.10+.
2. Open PowerShell in this folder.
3. Create and activate a virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

4. Install dependencies:

```powershell
pip install -r requirements.txt
```

5. Start the honeypot (use a local-only bind for this test):

```powershell
py honeypot.py --host 127.0.0.1 --port 2222 --accept-after 1
```

6. Open a second PowerShell window in the same folder, activate the environment, and run:

```powershell
py test_client.py 127.0.0.1 2222
```

7. Generate a report:

```powershell
py analyze.py logs/honeypot.jsonl --out report.md
```

The report excludes raw password values. The original JSONL log still contains attempted passwords; keep it private.

## Run with Docker

Install Docker Desktop, then run from this folder:

```bash
docker compose up --build -d
docker compose logs -f
```

The container listens on host port `2222`. A named Docker volume stores logs and the generated SSH host key. Stop with:

```bash
docker compose down
```

## Configuration

| Option | Default | Description |
|---|---:|---|
| `--host` | `0.0.0.0` | Bind address |
| `--port` | `2222` | Listening port |
| `--log-file` | `logs/honeypot.jsonl` | JSONL event log |
| `--host-key` | `host_key.pem` | SSH server private key |
| `--accept-after` | `3` | Accept after this many attempts from a source IP; `0` never accepts |
| `--max-connections` | `50` | Concurrent connection limit |
| `--session-timeout` | `120` | Maximum shell session duration |
| `--max-commands` | `50` | Maximum commands per shell session |

## Security notes

- Use only dummy credentials.
- Do not deploy on your everyday laptop or home network.
- Never publish `logs/`, `data/`, `*.jsonl`, `*.pem`, or reports containing sensitive data.
- For internet-facing deployment, use a disposable VPS, restrict outbound traffic, and check your provider's acceptable-use policy.
- Docker maps port `2222` to `2222`; it does not take over host SSH port 22.

## MITRE ATT&CK examples

| Observed behavior | Technique |
|---|---|
| Repeated password guessing | T1110.001 – Password Guessing |
| Default/common account use | T1078.001 – Default Accounts |
| `uname`, `id`, `whoami` | T1082 – System Information Discovery; T1033 – System Owner/User Discovery |
| `wget` / `curl` command attempts | T1105 – Ingress Tool Transfer |
| Reading `/etc/passwd` | T1087.001 – Local Account Discovery |

## Limitations

This is a low-interaction educational honeypot. Its limited fake shell can be fingerprinted and it does not emulate a complete operating system.

## License

MIT
