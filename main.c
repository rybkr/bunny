#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>

static constexpr size_t MAX_HOPS = 32;

typedef enum reply_type {
    REPLY_TIMEOUT,
    REPLY_ROUTER,
    REPLY_DESTINATION,
    REPLY_UNREACHABLE,
    REPLY_TCP_ERROR,
} reply_type_t;

typedef struct reply {
    reply_type_t   type;
    struct in_addr address;
    double         elapsed_ms;
    int            error;
    unsigned       icmp_code;
    int            port_open;
} reply_t;

static struct sockaddr_in resolve_destination(const char *host, const char *port);
static int trace_route(const struct sockaddr_in *remote);

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s host [port=443]\n", argv[0]);
        return EXIT_FAILURE;
    }

    setvbuf(stdout, NULL, _IONBF, 0);

    struct sockaddr_in remote = resolve_destination(argv[1], argc == 3 ? argv[2] : "443");
    return trace_route(&remote);
}

static struct sockaddr_in resolve_destination(const char *host, const char *port) {
    struct sockaddr_in address;
    return address;
}

static int trace_route(const struct sockaddr_in *remote) {
    return 0;
}
