# DNP3 outstation simulator — hand-rolled Data-Link + minimal App layer.
# No pip dependencies (stdlib only) — see server.py for rationale.
FROM python:3.11-slim

WORKDIR /app
COPY server.py /app/server.py

EXPOSE 20000/tcp
CMD ["python", "-u", "/app/server.py"]
