# sslkeylog
This is a patched version of Peter Lekensteyn's [sslkeylog](https://github.com/Lekensteyn/wireshark-notes) supporting advanced logging, SNI and client/server filtering.
Contrary to the original version it requires OpenSSL 1.1.1.
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
env LD_PRELOAD=/path/to/libsslkeylog.so;
env SSLKEYLOGISSERVER=1;
env SSLKEYLOGFILE=/tmp/sslkeylog/nginx;
```
Note that `LD_PRELOAD` **must be set in both places** to support both systemd service startup and `SIGUSR2`-induced restart that is used by the nginx binary upgrade script.

## Log format
Logs are created each minute, the name is prefixed with SSLKEYLOGFILE, then suffixed with minute-precision timestamp and process PID.
The log line format is as follows:
```
<rfc3339_timestamp> <source_ip>:<source_port> <destination_ip>:<destination_port> <sni> <hex_cipher_suite> <server_random> <client_random> <premaster>
```
The `sni` field can be empty if there was no `ClientHello` exchange. Also source IP+port and destination IP+port may be absent and replaced with `?` if it was impossible to determine the address (for example because the socket was closed).
The `hex_cipher_suite` uses hexadecimap representation.
The `server_random`, `client_random` and `premaster` fields are hex-encoded in the same way as `CLIENT_RANDOM` in [NSS Key log format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format).

Example line:
```
2021-07-22T15:52:07Z 10.14.32.138:46342 10.224.132.47:443 www.example.net c02b 23865af0f34f3615ee3486126a82ec624b3fdaa439696913737ead1c91e6c98f b6bee7a85cf13cd687b413103484f8595c4878029658232ce9419bb9202954d6 a23e5822a16c965f9cee67dcb899b142bded9eb0826efbcb99c837b2a05ee48efdd4327659f3394fcb8e4a9d105dfa48
```