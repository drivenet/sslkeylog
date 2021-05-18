# sslkeylog
This is a patched version of Peter Lekensteyn's [sslkeylog](https://git.lekensteyn.nl/peter/wireshark-notes/src/) supporting advanced logging, SNI and client/server filtering.
Take a look at [sslkeylog-processor](https://github.com/drivenet/sslkeylog-processor) to convert/persist logs produced by this utility.

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

## Log format
Logs are created each minute, the name is prefixed with SSLKEYLOGFILE, then suffixed with minute-precision timestamp and process PID.
The log line format is as follows:
```
<rfc3339_timestamp> <source_ip>:<source_port> <destination_ip>:<destination_port> <sni> <hex_cipher_suite> <server_random> <client_random> <premaster>
```
The `sni` field can be empty if there was no `ClientHello` exchange. Also source IP+port and destination IP+port may be absent and replaced with `?` if it was impossible to determine the address (for example because the socket was closed).
The `hex_cipher_suite` uses hexadecimap representation..
The `server_random`, `client_random` and `premaster` fields are hex-encoded in the same way as `CLIENT_RANDOM` in [NSS Key log format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format).
