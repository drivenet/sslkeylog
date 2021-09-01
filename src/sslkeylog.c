/*
 * Dumps master keys for OpenSSL clients to file. The format is documented at
 * https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format,
 * but contains some extensions like source/destination IP addresses, ports and
 * SNI information. Requires OpenSSL 1.1.1.
 *
 * Copyright (C) 2014 Peter Wu <peter@lekensteyn.nl>
 * Logging expanded and improved by Aristarkh Zagorodnikov <xm@drive.net>
 * Licensed under the terms of GPLv3 (or any later version) at your choice.
 *
 * Usage:
 *  cc sslkeylog.c -shared -o libsslkeylog.so -fPIC -ldl
 *  SSLKEYLOGFILE=premaster.txt LD_PRELOAD=./libsslkeylog.so openssl ...
 *
 * Also SSLKEYLOGISSERVER can be set to 0 or 1 to filter client-only or 
 * server-only contexts.
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
#include <sys/stat.h>
#include <sys/time.h>

#define CLIENT_RANDOM "CLIENT_RANDOM "

static FILE* keylog_file = NULL;
static const char* keylog_name = NULL;

static void init_keylog_file(const struct tm* const now)
{
    const char* filename = getenv("SSLKEYLOGFILE");
    if (filename) {
        if (strlen(filename) > PATH_MAX - 100) {
            fputs("sslkeylog: The provided log file name is too long\n", stderr);
            return;
        }

        char buffer[PATH_MAX];
        snprintf(buffer,
            sizeof(buffer),
            "%s-%04u%02u%02u%02u%02u_%u", 
            filename,
            1900 + now->tm_year, 
            now->tm_mon + 1, 
            now->tm_mday, 
            now->tm_hour, 
            now->tm_min,
            getpid());
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
        if (keylog_file) {
            keylog_name = strdup(filename);
            struct stat file_stat;
            if (stat(filename, &file_stat)) {
                fprintf(stderr, "sslkeylog: Failed to stat file %s, errno: %d\n", filename, errno);
            } else {
                const mode_t new_mode = file_stat.st_mode & ~(S_IROTH | S_IWOTH | S_IXOTH);
                if (new_mode != file_stat.st_mode) {
                    if (chmod(filename, new_mode)) {
                        fprintf(stderr, "sslkeylog: Failed to set permissions for file %s, errno: %d\n", filename, errno);
                    }
                }
            }
            setlinebuf(keylog_file);
        } else {
            fprintf(stderr, "sslkeylog: Failed to open file %s, errno: %d\n", filename, errno);
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

static void log_addr(const struct sockaddr* const addr)
{
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

static void log_timestamp(const struct tm* const now)
{
    fprintf(keylog_file, 
        "%04u-%02u-%02uT%02u:%02u:%02uZ", 
        1900 + now->tm_year, 
        now->tm_mon + 1, 
        now->tm_mday, 
        now->tm_hour, 
        now->tm_min, 
        now->tm_sec);
}

static inline void fputch(unsigned char c, FILE* const stream)
{
    unsigned char c1 = c >> 4;
    fputc(c1 < 10 ? '0' + c1 : 'a' + c1 - 10, stream);
    unsigned char c2 = c & 0xF;
    fputc(c2 < 10 ? '0' + c2 : 'a' + c2 - 10, stream);
}

/* Key extraction via the new OpenSSL 1.1.1 API. */
static void keylog_callback(const SSL* const ssl, const char* line)
{
    time_t now_time = time(NULL);
    const int is_server = SSL_is_server(ssl);
    const char* const is_server_var = getenv("SSLKEYLOGISSERVER");
    if (is_server_var) {        
        if (!strcmp(is_server_var, "1")) {
            if (!is_server) {
                return;
            }
        } else if (!strcmp(is_server_var, "0")) {
            if (is_server) {
                return;
            }
        }
    }

    struct tm now;
    gmtime_r(&now_time, &now);

    if (strncmp(CLIENT_RANDOM, line, sizeof(CLIENT_RANDOM) - 1)) {
        return;
    }

    line += sizeof(CLIENT_RANDOM) - 1;


    init_keylog_file(&now);
    if (!keylog_file) {
        return;
    }

    int peer_fd = SSL_get_fd(ssl);
    if (peer_fd >= 0) {
        struct sockaddr peer_addr_buffer;
        socklen_t addr_len = sizeof(peer_addr_buffer);
        const struct sockaddr* const peer_addr = 
            getpeername(peer_fd, &peer_addr_buffer, &addr_len) ? NULL : &peer_addr_buffer;
        if (!peer_addr && is_server && errno == ENOTCONN) {
            // There is no need to log anything if connection from client is broken
            return;
        }

        struct sockaddr sock_addr_buffer;
        addr_len = sizeof(sock_addr_buffer);
        const struct sockaddr* const sock_addr = 
            getsockname(peer_fd, &sock_addr_buffer, &addr_len) ? NULL : &sock_addr_buffer;
        if (!sock_addr && !is_server && errno == ENOTCONN) {
            // There is no need to log anything if connection to server is broken
            return;
        }
        
        log_timestamp(&now);

        fputc(' ', keylog_file);

        if (peer_addr) {
            log_addr(peer_addr);
        } else {
            fprintf(stderr, "sslkeylog: Failed to get peer name for fd %d, errno: %d\n", peer_fd, errno);
            fputs("?:?", keylog_file);
        }

        fputc(' ', keylog_file);

        if (sock_addr) {
            log_addr(sock_addr);
        } else {
            fprintf(stderr, "sslkeylog: Failed to get socket name for fd %d, errno: %d\n", peer_fd, errno);
            fputs("?:?", keylog_file);
        }
    } else {
        fprintf(stderr, "sslkeylog: Failed to get fd for SSL, errno: %d\n", errno);
        log_timestamp(&now);

        fputc(' ', keylog_file);

        fputs("?:? ?:?", keylog_file);
    }

    fputc(' ', keylog_file);

    const char* client_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (client_name) {
        const size_t length = strlen(client_name);
        if (length <= 255)
        {
            for (size_t i = 0;i < length;++i)
            {
                const char ch = client_name[i];
                if (!(ch == '.' || ch == '-' || ch == '_'
                    || (ch >= '0' && ch <= '9')
                    || (ch >= 'A' && ch <= 'Z')
                    || (ch >= 'a' && ch <= 'z')))
                {
                    client_name = NULL;
                    break;
                }
            }
        }
        else
        {
            client_name = NULL;
        }

        if (client_name) {
            fputs(client_name, keylog_file);
        } else {
            fputc('?', keylog_file);
        }
    }

    fputc(' ', keylog_file);

    const SSL_CIPHER* const cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        fprintf(keylog_file, "%04x", SSL_CIPHER_get_protocol_id(cipher));
    } else {
        fprintf(stderr, "sslkeylog: Failed to get current cipher\n");
        fputc('?', keylog_file);
    }

    fputc(' ', keylog_file);

    unsigned char server_random[SSL3_RANDOM_SIZE];
    if (SSL_get_server_random(ssl, server_random, sizeof(server_random)) == sizeof(server_random)) {
        for (size_t i = 0; i < sizeof(server_random); i++) {
            fputch(server_random[i], keylog_file);
        }
    } else {
        fprintf(stderr, "sslkeylog: Failed to get SERVER_RANDOM\n");
        fputc('?', keylog_file);
    }

    fputc(' ', keylog_file);

    fputs(line, keylog_file);

    fputc('\n', keylog_file);
}

SSL* SSL_new(SSL_CTX* const ctx)
{
    static SSL*(*func)(SSL_CTX*);
    if (!func) {        
        *(void**)(&func) = dlsym(RTLD_NEXT, __func__);
        if (!func) {
            fprintf(stderr, "sslkeylog: Cannot lookup %s\n", __func__);
            abort();
        }
    }
    /* Override any previous key log callback. */
    SSL_CTX_set_keylog_callback(ctx, keylog_callback);
    return func(ctx);
}

SSL_CTX *SSL_set_SSL_CTX(SSL* const ssl, SSL_CTX* const ctx)
{
    static SSL_CTX*(*func)(SSL*, SSL_CTX*);
    if (!func) {        
        *(void**)(&func) = dlsym(RTLD_NEXT, __func__);
        if (!func) {
            fprintf(stderr, "sslkeylog: Cannot lookup %s\n", __func__);
            abort();
        }
    }
    /* Override any previous key log callback. */
    SSL_CTX_set_keylog_callback(ctx, keylog_callback);
    return func(ssl, ctx);
}
