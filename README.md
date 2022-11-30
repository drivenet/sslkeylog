# sslkeylog
This is a patched version of Peter Lekensteyn's [sslkeylog](https://github.com/Lekensteyn/wireshark-notes/tree/master/src) supporting advanced logging, SNI and client/server filtering.
Contrary to the original version it requires OpenSSL 1.1.1.
Take a look at [sslkeylog-processor](https://github.com/drivenet/sslkeylog-processor) to convert/persist logs produced by this utility.

## Building
```shell
cd src
CFLAGS=-O3 make
```

## Installation for nginx
`/lib/systemd/system/nginx.service.d/override.conf`:
```ini
[Service]
Environment=LD_PRELOAD=/path/to/libsslkeylog.so
```

`nginx.conf`:
```text
env LD_PRELOAD=/path/to/libsslkeylog.so;
env SSLKEYLOGISSERVER=1;
env SSLKEYLOGFILE=/tmp/sslkeylog/nginx;
```
Note that `%LD_PRELOAD%` **must be set in both places** to support both systemd service startup and `SIGUSR2`-induced restart that is used by the nginx binary upgrade script.

## Log format
Logs are created every second, the name is prefixed with `%SSLKEYLOGFILE%`, then suffixed with second-precision timestamp and PID.
The log line format is as follows:
```text
# TLS pre-1.3
<rfc3339_timestamp> <source_ip>:<source_port> <destination_ip>:<destination_port> <sni> <hex_cipher_suite> <server_random> <client_random> <premaster>
# TLS 1.3
<rfc3339_timestamp> <source_ip>:<source_port> <destination_ip>:<destination_port> <sni> <hex_cipher_suite> <server_random> <client_random> <server_handshake> <client_handshake> <server_0> <client_0>
```
The `sni` field can be empty if there was no `ClientHello` exchange. Also source IP+port and destination IP+port may be absent and replaced with `?` if it was impossible to determine the address (for example because the socket was closed).
The `hex_cipher_suite` uses hexadecimal representation.
The `server_random` and all fields that follow it are hex-encoded in the same way as `CLIENT_RANDOM` in [NSS Key log format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format).

Example line:
```text
2021-07-22T15:52:07Z 10.14.32.138:46342 10.224.132.47:443 www.example.net c02b 23865af0f34f3615ee3486126a82ec624b3fdaa439696913737ead1c91e6c98f b6bee7a85cf13cd687b413103484f8595c4878029658232ce9419bb9202954d6 a23e5822a16c965f9cee67dcb899b142bded9eb0826efbcb99c837b2a05ee48efdd4327659f3394fcb8e4a9d105dfa48
2022-11-30T07:13:57Z 10.14.32.138:59170 10.224.132.47:443 www.example.net 1302 fb8c0226d50e6b8f33dc6224056b823fd4bd8358186499180dbc6f79260b0f29 af7c0a854e11ccaa8115081abaa7b2e5e456cfdbeb027970f874a124268a1fb4 a31c59aa5ff53495b4942b99976611eed8a900fe3409b2e5b41c0767745344841e85995da0b056afae1df4050f9e787a d9161ad278ea3040fac3bc668cea8dace544075e24a93ff4d450faa98d7361d2b4d20981ea3a25c3a573271f935f12b6 8c46d28a874a05d754ab12112884283e36ed2b4aeebb7064ebcc76bcffd52219de4c4cdf3c1a73747bb518036a4d3165 00940a0a10c72b6105b754d7cddd36cfc7f33532985b6ab1ecbfdc1c64a7b936dbbffab54ac146581294eec49beab7a3
```

## Implementation notes
The utility fixes the log recording race condition for multi-process applications like nginx and haproxy by suffixing the log file name with PID. Still, it is not thread-safe with respect to the file logging process, hybrid process models like Apache threaded MPMs are not handled well. This is quite easy to fix by modifying the log file name generation logic, but for optimal performance this will require a per-thread log file cache and will add a dependency on `libpthread`, which is less than desirable for most of the use cases.
