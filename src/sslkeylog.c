/*
 * Dumps master keys for OpenSSL clients to file. The format is documented at
 * https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
 * Supports TLS 1.3 when used with OpenSSL 1.1.1.
 *
 * Copyright (C) 2014 Peter Wu <peter@lekensteyn.nl>
 * Licensed under the terms of GPLv3 (or any later version) at your choice.
 *
 * Usage:
 *  cc sslkeylog.c -shared -o libsslkeylog.so -fPIC -ldl
 *  SSLKEYLOGFILE=premaster.txt LD_PRELOAD=./libsslkeylog.so openssl ...
 *
 * Usage for macOS:
 *  cc sslkeylog.c -shared -o libsslkeylog.dylib -fPIC -ldl \
 *      -I/usr/local/opt/openssl@1.1/include \
 *      -L/usr/local/opt/openssl@1.1/lib -lssl
 *  DYLD_INSERT_LIBRARIES=./libsslkeylog.dylib DYLD_FORCE_FLAT_NAMESPACE=1 \
 *      SSLKEYLOGFILE=premaster.txt /usr/local/opt/openssl@1.1/bin/openssl ...
 */

#define _GNU_SOURCE /* for RTLD_NEXT */
#include <dlfcn.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>

#define CLIENT_RANDOM "CLIENT_RANDOM "

static FILE* keylog_file = NULL;
static const char* keylog_name = NULL;

static void init_keylog_file(const struct tm* now)
{
    const char *filename = getenv("SSLKEYLOGFILE");
    if (filename) {
        if (strlen(filename) > PATH_MAX - 100) {
            fputs("sslkeylog: The provided log file name is too long\n", stderr);
            return;
        }

        char buffer[PATH_MAX];
        snprintf(buffer,
            sizeof(buffer),
            "%s[%u-%04u%02u%02u%02u%02u]", 
            filename,
            getpid(),
            1900 + now->tm_year, 
            now->tm_mon + 1, 
            now->tm_mday, 
            now->tm_hour, 
            now->tm_min);
        filename = buffer;

        if (keylog_file) {
            if (!strcmp(keylog_name, filename)) {
                return;
            }
            fclose(keylog_file);
            keylog_file = NULL;
            free((void*)keylog_name);
            keylog_name = NULL;
        }

        keylog_file = fopen(filename, "a");
        if (keylog_file >= 0) {
            keylog_name = strdup(filename);
            setlinebuf(keylog_file);
        }
    } else {
        if (keylog_file) {
            fclose(keylog_file);
            keylog_file = NULL;
        }
        if (keylog_name) {
            free((void*)keylog_name);
            keylog_name = NULL;
        }
    }
}

static void log_addr(const struct sockaddr* addr) {
    const char* addr_name;
    unsigned short port;
    char buffer[INET6_ADDRSTRLEN];
    switch (addr->sa_family)
    {
        case AF_INET:
            addr_name = inet_ntop(AF_INET, &((struct sockaddr_in*)addr)->sin_addr, buffer, sizeof(buffer));
            port = ntohs(((struct sockaddr_in*)addr)->sin_port);
            break;

        case AF_INET6:
            addr_name = inet_ntop(AF_INET6, &((struct sockaddr_in6*)addr)->sin6_addr, buffer, sizeof(buffer));
            port = ntohs(((struct sockaddr_in6*)addr)->sin6_port);
            break;

        default:
            addr_name = NULL;
            port = 0;
            break;
    }

    if (addr_name) {
        fputs(addr_name, keylog_file);
    } else {
        fprintf(stderr, "sslkeylog: Failed to convert address, AF: %hu, errno: %d\n", addr->sa_family, errno);
        fputc('?', keylog_file);
    }

    if (port != 0) {
        fprintf(keylog_file, ":%hu", port);
    }
}

/* Key extraction via the new OpenSSL 1.1.1 API. */
static void keylog_callback(const SSL *ssl, const char *line)
{
    long session_tme = SSL_get_time(SSL_get_session(ssl));
    struct tm now;
    gmtime_r(&session_tme, &now);

    init_keylog_file(&now);
    if (!keylog_file) {
        return;
    }

    fprintf(keylog_file, 
        "%04u-%02u-%02uT%02u:%02u:%02uZ ", 
        1900 + now.tm_year, 
        now.tm_mon + 1, 
        now.tm_mday, 
        now.tm_hour, 
        now.tm_min, 
        now.tm_sec);

    int peer_fd = SSL_get_fd(ssl);
    if (peer_fd >= 0) {
        struct sockaddr addr;
        socklen_t addr_len = sizeof(addr);
        if (getpeername(peer_fd, &addr, &addr_len) == 0) {
            log_addr(&addr);
        } else {
            fprintf(stderr, "sslkeylog: Failed to get peer name for fd %d, errno: %d\n", peer_fd, errno);
            fputc('?', keylog_file);
        }

        fputc(' ', keylog_file);

        addr_len = sizeof(addr);
        if (getsockname(peer_fd, &addr, &addr_len) == 0) {
            log_addr(&addr);
        }
        else {
            fprintf(stderr, "sslkeylog: Failed to get socket name for fd %d, errno: %d\n", peer_fd, errno);
            fputc('?', keylog_file);
        }
    } else {
        fprintf(stderr, "sslkeylog: Failed to get fd for SSL, errno: %d\n", errno);
        fputs("? ?", keylog_file);
    }

    fputc(' ', keylog_file);

    const char* client_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (client_name) {
        fputs(client_name, keylog_file);
    }

    fputc(' ', keylog_file);

    if (!strncmp(CLIENT_RANDOM, line, sizeof(CLIENT_RANDOM) - 1)) {
        line += sizeof(CLIENT_RANDOM) - 1;
    }
    fputs(line, keylog_file);

    fputc('\n', keylog_file);
}

SSL *SSL_new(SSL_CTX *ctx)
{
    static SSL *(*func)();
    if (!func) {        
        func = dlsym(RTLD_NEXT, __func__);
        if (!func) {
            fprintf(stderr, "sslkeylog: Cannot lookup %s\n", __func__);
            abort();
        }
    }
    /* Override any previous key log callback. */
    SSL_CTX_set_keylog_callback(ctx, keylog_callback);
    return func(ctx);
}
