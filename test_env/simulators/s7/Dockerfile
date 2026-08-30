# Siemens S7 simulator — python-snap7 wrapping the libsnap7 C library.
# libsnap7 is not in Debian; build it from the upstream Sourceforge tarball.
FROM python:3.11-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential wget ca-certificates p7zip-full \
 && wget -q -O /tmp/snap7.7z \
        https://sourceforge.net/projects/snap7/files/1.4.2/snap7-full-1.4.2.7z/download \
 && 7z x -o/tmp /tmp/snap7.7z \
 && cd /tmp/snap7-full-1.4.2/build/unix \
 && make -f x86_64_linux.mk \
 && cp ../bin/x86_64-linux/libsnap7.so /usr/lib/libsnap7.so \
 && ldconfig \
 && apt-get purge -y --auto-remove build-essential wget p7zip-full \
 && rm -rf /tmp/snap7* /var/lib/apt/lists/*

RUN pip install --no-cache-dir python-snap7==1.3

WORKDIR /app
COPY server.py /app/server.py

EXPOSE 102/tcp
CMD ["python", "-u", "/app/server.py"]
