FROM python:3.12-slim

RUN useradd --create-home --shell /usr/sbin/nologin honeypot
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY honeypot.py analyze.py ./
RUN mkdir -p /data && chown -R honeypot:honeypot /data
VOLUME ["/data"]
USER honeypot
EXPOSE 2222
CMD ["python", "honeypot.py", "--host", "0.0.0.0", "--port", "2222", "--log-file", "/data/honeypot.jsonl", "--host-key", "/data/host_key.pem"]
