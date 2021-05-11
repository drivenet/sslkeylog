# sslkeylog
This is a patched version of Peter Lekensteyn's [sslkeylog](https://git.lekensteyn.nl/peter/wireshark-notes/src/) supporting advanced logging, SNI and client/server filtering.

## Building
`CFLAGS=-O3 make`

## Installation for nginx
/lib/systemd/system/nginx.service.d/override.conf:
```
[Service]
Environment=LD_PRELOAD=/path/to/libsslkeylog.so
```
nginx.conf:
```
env SSLKEYLOGISSERVER=1;
env SSLKEYLOGFILE=/tmp/sslkeylog/nginx;
```
