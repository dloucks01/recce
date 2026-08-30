# EtherNet/IP simulator — encapsulation responder for List Identity /
# List Services / RegisterSession. Stdlib-only, no pip dependencies.
FROM python:3.11-slim

WORKDIR /app
COPY server.py /app/server.py

EXPOSE 44818/tcp
CMD ["python", "-u", "/app/server.py"]
