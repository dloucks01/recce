# BACnet/IP simulator — bacpypes-based Device with Analog-Value + File objects.
# Answers Who-Is and ReadProperty against recce's `bacnet` module.
FROM python:3.11-slim

RUN pip install --no-cache-dir bacpypes==0.18.7

WORKDIR /app
COPY server.py /app/server.py

EXPOSE 47808/udp
CMD ["python", "-u", "/app/server.py"]
