# Telnet target — busybox telnetd on :23 with a root:toor login shell.
# Exercises recce.services.telnet: IAC negotiation fingerprint,
# no-encryption emission, banner disclosure, and (once the tester
# supplies -u root -p toor) the default-creds / credentialed-shell path.
#
# Deliberately unhardened: cleartext protocol + trivial creds. Never
# deploy this outside a lab.
FROM alpine:3.20

RUN apk add --no-cache busybox-extras shadow \
    && echo 'root:toor' | chpasswd \
    && sed -i 's|root:x:0:0:root:/root:.*|root:x:0:0:root:/root:/bin/sh|' /etc/passwd \
    && printf '%s\n' \
        'recce-lab telnetd' \
        'Unauthorized access prohibited.' \
        > /etc/issue.net

# busybox telnetd's -l flag hands the connection to /bin/login, which
# reads /etc/passwd + /etc/shadow.  -F keeps it in the foreground so
# Docker can supervise it directly.
EXPOSE 23/tcp
CMD ["/usr/sbin/telnetd", "-F", "-l", "/bin/login", "-b", "0.0.0.0:23"]
