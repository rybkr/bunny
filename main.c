#include <stdio.h>
#include <stdlib.h>

#include "traceroute.h"

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s host [port=443]\n", argv[0]);
        return EXIT_FAILURE;
    }

    return traceroute(argv[1], argc == 3 ? argv[2] : "443");
}
