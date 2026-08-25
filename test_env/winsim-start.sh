#!/bin/bash
# Simulate Windows services for scan detection

# RDP on 3389 — send RDP negotiation response header
ncat -lk 3389 --exec '/bin/echo -ne "\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x01\x08\x00\x02\x00\x00\x00"' &

# WinRM on 5985 — respond as HTTP
ncat -lk 5985 -c 'echo -e "HTTP/1.1 200 OK\r\nServer: Microsoft-HTTPAPI/2.0\r\nContent-Length: 0\r\n\r\n"' &

wait
