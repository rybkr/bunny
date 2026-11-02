#include "traceroute.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp_var.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

static constexpr int MAX_HOPS   = 32;
static constexpr int TIMEOUT_MS = 2000;

typedef enum reply_kind {
    REPLY_TIMEOUT,
    REPLY_ROUTER,
    REPLY_DESTINATION,
    REPLY_UNREACHABLE,
    REPLY_TCP_ERROR,
} reply_kind_t;

typedef struct reply {
    reply_kind_t   kind;
    struct in_addr address;
    double         elapsed_ms;
    int            error;
    unsigned       icmp_code;
    int            port_open;
} reply_t;

static void   die(const char *s);
static double now_ms();

static int open_icmp_listener();
static int open_probe_socket(int ttl, in_port_t source_port);
static int start_conn(int tcp, const struct sockaddr_in *remote);

static struct sockaddr_in local_address(int tcp);
static bool    initial_sequence(const struct sockaddr_in *local, const struct sockaddr_in *remote,
                                uint32_t *sequence);
static int     match_icmp(const unsigned char *p, size_t n, const struct sockaddr_in *local,
                          const struct sockaddr_in *remote, uint32_t sequence, unsigned *code);
static bool    receive_icmp(int icmp, const struct sockaddr_in *local,
                            const struct sockaddr_in *remote, uint32_t sequence, reply_t *reply);
static reply_t wait_for_reply(int icmp, int tcp, const struct sockaddr_in *remote, double start,
                              int initial_error);

static reply_t probe(int icmp, const struct sockaddr_in *remote, int ttl, in_port_t *source_port);
static struct sockaddr_in resolve_destination(const char *host, const char *port);
static int                trace_route(const struct sockaddr_in *remote);
static void               print_reply(const reply_t *reply);

bool traceroute(const char *host, const char *port) {
    struct sockaddr_in remote = resolve_destination(host, port);
    return trace_route(&remote);
}

static void die(const char *s) {
    perror(s);
    exit(EXIT_FAILURE);
}

static double now_ms() {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) < 0) {
        die("error: clock_gettime: could not get time");
    }
    return t.tv_sec * 1000.0 + t.tv_nsec / 1000000.0;
}

static int open_icmp_listener() {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) {
        die("error: could not open ICMP socket");
    }
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, (flags | O_NONBLOCK)) < 0) {
        die("error: fcntl: could not make ICMP socket non-blocking");
    }
    return fd;
}

static int open_probe_socket(int ttl, in_port_t source_port) {
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        die("error: could not open TCP socket");
    }
    struct sockaddr_in local = {0};
    local.sin_family         = AF_INET;
    local.sin_port           = source_port;
    if (bind(fd, (const struct sockaddr *)&local, sizeof local) < 0) {
        die("error: bind: could not bind TCP source port");
    }
    if (setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, (sizeof ttl)) < 0) {
        die("error: IP_TTL: could not set ttl for TCP socket");
    }
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, (flags | O_NONBLOCK)) < 0) {
        die("error: fcntl: could not make TCP socket non-blocking");
    }
    return fd;
}

static int start_conn(int tcp, const struct sockaddr_in *remote) {
    if (connect(tcp, (const struct sockaddr *)remote, sizeof *remote) != 0) {
        return errno;
    }
    return 0;
}

static struct sockaddr_in local_address(int tcp) {
    struct sockaddr_in address;
    socklen_t          size = (sizeof address);
    if (getsockname(tcp, (struct sockaddr *)&address, &size) < 0) {
        die("error: getsockname: could not get socket name");
    }
    return address;
}

static bool initial_sequence(const struct sockaddr_in *local, const struct sockaddr_in *remote,
                             uint32_t *sequence) {
    // macOS's TCP_CONNECTION_INFO does not expose sequence numbers. The
    // exported TCP control block includes the SYN's initial sequence number
    // (iss).
    unsigned char *data;
    size_t         size;
    for (;;) {
        size = 0;
        if (sysctlbyname("net.inet.tcp.pcblist64", NULL, &size, NULL, 0) < 0) {
            die("error: sysctl: could not size TCP connection table");
        }
        data = malloc(size);
        if (!data) {
            die("error: malloc: could not allocate TCP connection table");
        }
        if (sysctlbyname("net.inet.tcp.pcblist64", data, &size, NULL, 0) == 0) {
            break;
        }
        int error = errno;
        free(data);
        if (error != ENOMEM) {
            errno = error;
            die("error: sysctl: could not read TCP connection table");
        }
        // Connections can be added between the size query and the snapshot.
    }

    bool found = false;
    for (size_t offset = 0; size - offset >= sizeof(uint32_t);) {
        uint32_t length;
        memcpy(&length, data + offset, sizeof length);
        if (length < sizeof length || length > size - offset) {
            break;
        }
        if (length == sizeof(struct xtcpcb64)) {
            struct xtcpcb64 entry;
            memcpy(&entry, data + offset, sizeof entry);
            const struct xinpcb64 *inp = &entry.xt_inpcb;
            if ((inp->inp_vflag & INP_IPV4) && inp->inp_laddr.s_addr == local->sin_addr.s_addr &&
                inp->inp_faddr.s_addr == remote->sin_addr.s_addr &&
                inp->inp_lport == local->sin_port && inp->inp_fport == remote->sin_port) {
                *sequence = htonl(entry.iss);
                found     = true;
                break;
            }
        }
        offset += length;
    }
    free(data);
    return found;
}

static int match_icmp(const unsigned char *p, size_t n, const struct sockaddr_in *local,
                      const struct sockaddr_in *remote, uint32_t sequence, unsigned *code) {
    if (n < 20 || (p[0] >> 4) != 4 || p[9] != IPPROTO_ICMP) {
        return 0;
    }
    size_t outer = (p[0] & 15u) * 4u;
    if (outer < 20 || n < outer + 8 + 20) {
        return 0;
    }
    const unsigned char *icmp = p + outer;

    if (!((icmp[0] == 11 && icmp[1] == 0) || icmp[0] == 3)) {
        return 0;
    }
    const unsigned char *ip    = icmp + 8;
    size_t               inner = (ip[0] & 15u) * 4u;

    if ((ip[0] >> 4) != 4 || inner < 20 || n < outer + 8 + inner + 8 || ip[9] != IPPROTO_TCP) {
        return 0;
    }
    if ((ip[6] & 0x1f) || ip[7]) {
        return 0;
    }
    const unsigned char *tcp = ip + inner;

    if (memcmp(ip + 12, &local->sin_addr, 4) || memcmp(ip + 16, &remote->sin_addr, 4) ||
        memcmp(tcp, &local->sin_port, 2) || memcmp(tcp + 2, &remote->sin_port, 2) ||
        memcmp(tcp + 4, &sequence, sizeof sequence)) {
        return 0;
    }
    *code = icmp[1];
    return icmp[0] == 11 ? 1 : 2;
}

static bool receive_icmp(int icmp, const struct sockaddr_in *local,
                         const struct sockaddr_in *remote, uint32_t sequence, reply_t *reply) {
    unsigned char      packet[1u << 16];
    struct sockaddr_in sender;
    socklen_t          size = (sizeof sender);

    ssize_t n = recvfrom(icmp, packet, sizeof packet, 0, (struct sockaddr *)&sender, &size);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return false;
        }
        die("error: recvfrom: failed to receive");
    }

    unsigned code;
    int      kind = match_icmp(packet, (size_t)n, local, remote, sequence, &code);
    if (!kind) {
        return false;
    }

    reply->kind      = kind == 1 ? REPLY_ROUTER : REPLY_UNREACHABLE;
    reply->address   = sender.sin_addr;
    reply->icmp_code = code;
    return true;
}

static reply_t wait_for_reply(int icmp, int tcp, const struct sockaddr_in *remote, double start,
                              int initial_error) {
    reply_t reply = (reply_t){0};
    reply.address = remote->sin_addr;

    if (initial_error != EINPROGRESS) {
        reply.kind      = (!initial_error || initial_error == ECONNREFUSED) ? REPLY_DESTINATION
                                                                            : REPLY_TCP_ERROR;
        reply.port_open = (initial_error == 0);
        reply.error     = initial_error;
    } else {
        struct sockaddr_in local       = local_address(tcp);
        int                watched_tcp = tcp;
        uint32_t           sequence;
        // A fast TCP reply may already have removed the control block.
        // In that case, let the TCP socket report the result; never accept unmatched ICMP.
        int watched_icmp = initial_sequence(&local, remote, &sequence) ? icmp : -1;
        for (;;) {
            double remaining_ms = start + TIMEOUT_MS - now_ms();
            if (remaining_ms < 0) {
                break;
            }

            struct pollfd fds[] = {{watched_icmp, POLLIN, 0}, {watched_tcp, POLLOUT, 0}};
            int           ready = poll(fds, 2, (int)remaining_ms + 1);
            if (ready < 0) {
                if (errno == EINTR) {
                    continue;
                }
                die("error: failed to poll");
            }
            if (!ready) {
                break;
            }

            if (fds[0].revents & POLLIN) {
                if (receive_icmp(icmp, &local, remote, sequence, &reply)) {
                    break;
                }
                continue;
            }
            if (fds[1].revents & (POLLOUT | POLLERR | POLLHUP)) {
                int       conn_error;
                socklen_t size = (sizeof conn_error);
                if (getsockopt(tcp, SOL_SOCKET, SO_ERROR, &conn_error, &size) < 0) {
                    die("error: SO_ERROR: tcp socket error");
                }
                if (conn_error == EHOSTUNREACH) {
                    // This could mean TTL expiry. We'll let ICMP tell us what happened.
                    // Poll will ignore negative descriptors, hence skipping this.
                    watched_tcp = -1;
                    continue;
                }
                reply.kind      = (!conn_error || conn_error == ECONNREFUSED) ? REPLY_DESTINATION
                                                                              : REPLY_TCP_ERROR;
                reply.port_open = (conn_error == 0);
                reply.error     = conn_error;
                break;
            }
        }
    }

    reply.elapsed_ms = now_ms() - start;
    return reply;
}

static reply_t probe(int icmp, const struct sockaddr_in *remote, int ttl, in_port_t *source_port) {
    int tcp      = open_probe_socket(ttl, *source_port);
    *source_port = local_address(tcp).sin_port;

    double  start = now_ms();
    int     error = start_conn(tcp, remote);
    reply_t reply = wait_for_reply(icmp, tcp, remote, start, error);
    close(tcp);
    return reply;
}

static struct sockaddr_in resolve_destination(const char *host, const char *port) {
    struct addrinfo  hints = {0};
    struct addrinfo *result;

    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_NUMERICSERV;

    int error = getaddrinfo(host, port, &hints, &result);
    if (error) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in address = *(struct sockaddr_in *)result->ai_addr;
    freeaddrinfo(result);
    return address;
}

static int trace_route(const struct sockaddr_in *remote) {
    int  icmp    = open_icmp_listener();
    bool reached = false;
    // Let the first probe choose an ephemeral port, then reuse it for every hop.
    in_port_t source_port = 0;

    for (int ttl = 1; ttl <= MAX_HOPS; ++ttl) {
        printf("%2d  ", ttl);
        reply_t reply = probe(icmp, remote, ttl, &source_port);
        print_reply(&reply);
        if (reply.kind == REPLY_DESTINATION) {
            reached = true;
            break;
        } else if (reply.kind == REPLY_UNREACHABLE || reply.kind == REPLY_TCP_ERROR) {
            break;
        }
    }

    close(icmp);
    return reached ? EXIT_SUCCESS : EXIT_FAILURE;
}

static void print_reply(const reply_t *reply) {
    if (reply->kind == REPLY_TIMEOUT) {
        puts("*");
        return;
    }
    char address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &reply->address, address, sizeof(address));
    printf("%s  %.3f ms", address, reply->elapsed_ms);

    switch (reply->kind) {
    case REPLY_DESTINATION:
        printf("  [%s]", reply->port_open ? "open" : "closed");
        break;
    case REPLY_UNREACHABLE:
        printf("  [unreachable, ICMP code %u]", reply->icmp_code);
        break;
    case REPLY_TCP_ERROR:
        printf("  [TCP error: %s]", strerror(reply->error));
        break;
    default:
        break;
    }

    putchar('\n');
    fflush(stdout);
}
