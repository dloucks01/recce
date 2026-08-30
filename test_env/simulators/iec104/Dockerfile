# IEC 60870-5-104 simulator — APCI + U-format + minimal I-format responder.
# Stdlib-only, no pip dependencies.
FROM python:3.11-slim

WORKDIR /app
COPY server.py /app/server.py

EXPOSE 2404/tcp
CMD ["python", "-u", "/app/server.py"]
