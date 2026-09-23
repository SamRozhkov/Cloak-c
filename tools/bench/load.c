/* The measuring end: drives traffic through whatever is listening on the
 * given port and prints machine-readable numbers.
 *
 * WHAT IT DOES NOT DO, SO NOBODY READS MORE INTO ITS OUTPUT THAN IS IN IT.
 * It measures a round trip through an ALREADY ESTABLISHED tunnel. The
 * Cloak handshake happens once, between ck-client and ck-server, before
 * this program connects; none of its numbers include it. Handshake cost
 * needs its own harness and does not have one yet.
 *
 * TWO MODES, BECAUSE THROUGHPUT AND LATENCY DISAGREE ABOUT BUFFERING.
 *
 *   throughput -- one connection, `bytes` pushed out and the same count
 *      read back, with a poll() loop driving both directions at once. A
 *      write-everything-then-read-everything shape would deadlock the
 *      moment the payload exceeds the socket buffers, and a shape that
 *      avoids the deadlock by reading only after a short write measures
 *      the buffers rather than the tunnel.
 *
 *   latency -- `rounds` sequential small round trips, each one write and
 *      the matching read, nothing in flight. Reports the distribution,
 *      not a mean: a proxy's interesting failures live in the tail, and
 *      a mean hides exactly those.
 *
 * Every number is printed as key=value on its own line so a driver can
 * collect them without parsing prose. */

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static uint64_t mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int dial(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((uint16_t)port);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return fd;
}

static int read_full(int fd, char *buf, size_t want) {
    size_t got = 0;
    while (got < want) {
        ssize_t n = recv(fd, buf + got, want - got, 0);
        if (n > 0) {
            got += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

/* ---- throughput --------------------------------------------------------- */

static int run_throughput(int port, size_t bytes) {
    int fd = dial(port);
    if (fd < 0) {
        fprintf(stderr, "load: connect failed: %s\n", strerror(errno));
        return 1;
    }

    static char out[131072];
    static char in[131072];
    memset(out, 0x5a, sizeof(out));

    size_t sent = 0, received = 0;
    uint64_t t0 = mono_ns();

    while (received < bytes) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN | (sent < bytes ? POLLOUT : 0);
        pfd.revents = 0;
        if (poll(&pfd, 1, 60000) <= 0) {
            fprintf(stderr, "load: stalled at sent=%zu received=%zu\n", sent, received);
            close(fd);
            return 1;
        }
        if (pfd.revents & POLLOUT) {
            size_t chunk = bytes - sent;
            if (chunk > sizeof(out)) {
                chunk = sizeof(out);
            }
            ssize_t w = send(fd, out, chunk, MSG_NOSIGNAL);
            if (w > 0) {
                sent += (size_t)w;
            } else if (w < 0 && errno != EAGAIN && errno != EINTR) {
                fprintf(stderr, "load: send: %s\n", strerror(errno));
                close(fd);
                return 1;
            }
        }
        if (pfd.revents & POLLIN) {
            size_t chunk = bytes - received;
            if (chunk > sizeof(in)) {
                chunk = sizeof(in);
            }
            ssize_t n = recv(fd, in, chunk, 0);
            if (n > 0) {
                received += (size_t)n;
            } else if (n == 0) {
                fprintf(stderr, "load: peer closed at received=%zu\n", received);
                close(fd);
                return 1;
            } else if (errno != EAGAIN && errno != EINTR) {
                fprintf(stderr, "load: recv: %s\n", strerror(errno));
                close(fd);
                return 1;
            }
        }
    }

    uint64_t dt = mono_ns() - t0;
    close(fd);

    double secs = (double)dt / 1e9;
    /* Each payload byte crossed the tunnel twice, so the figure a reader
     * wants -- what one direction sustains -- is `bytes`, not 2*bytes,
     * over the elapsed time. Both are printed; neither is implied. */
    printf("mode=throughput\n");
    printf("bytes_each_way=%zu\n", bytes);
    printf("seconds=%.6f\n", secs);
    printf("mib_per_s_one_way=%.3f\n", (double)bytes / (1024.0 * 1024.0) / secs);
    printf("mib_per_s_both_ways=%.3f\n", 2.0 * (double)bytes / (1024.0 * 1024.0) / secs);
    return 0;
}

/* ---- latency ------------------------------------------------------------ */

static int run_latency(int port, int rounds, size_t size) {
    int fd = dial(port);
    if (fd < 0) {
        fprintf(stderr, "load: connect failed: %s\n", strerror(errno));
        return 1;
    }

    char *out = malloc(size), *in = malloc(size);
    uint64_t *samples = malloc((size_t)rounds * sizeof(uint64_t));
    if (out == NULL || in == NULL || samples == NULL) {
        fprintf(stderr, "load: out of memory\n");
        return 1;
    }
    memset(out, 0x5a, size);

    /* Ten warm-up round trips, discarded. The first one through a fresh
     * tunnel pays for things that happen once -- the proxy's upstream
     * dial among them -- and including it would put a one-off in a
     * distribution that claims to describe steady state. */
    for (int i = 0; i < 10; i++) {
        if (send(fd, out, size, MSG_NOSIGNAL) != (ssize_t)size || read_full(fd, in, size) != 0) {
            fprintf(stderr, "load: warm-up round trip failed\n");
            return 1;
        }
    }

    for (int i = 0; i < rounds; i++) {
        uint64_t t0 = mono_ns();
        if (send(fd, out, size, MSG_NOSIGNAL) != (ssize_t)size || read_full(fd, in, size) != 0) {
            fprintf(stderr, "load: round trip %d failed\n", i);
            return 1;
        }
        samples[i] = mono_ns() - t0;
    }
    close(fd);

    qsort(samples, (size_t)rounds, sizeof(uint64_t), cmp_u64);
    double mean = 0;
    for (int i = 0; i < rounds; i++) {
        mean += (double)samples[i];
    }
    mean /= rounds;

    printf("mode=latency\n");
    printf("rounds=%d\n", rounds);
    printf("payload_bytes=%zu\n", size);
    printf("us_min=%.1f\n", (double)samples[0] / 1000.0);
    printf("us_p50=%.1f\n", (double)samples[rounds / 2] / 1000.0);
    printf("us_p95=%.1f\n", (double)samples[(int)(rounds * 0.95)] / 1000.0);
    printf("us_p99=%.1f\n", (double)samples[(int)(rounds * 0.99)] / 1000.0);
    printf("us_max=%.1f\n", (double)samples[rounds - 1] / 1000.0);
    printf("us_mean=%.1f\n", mean / 1000.0);
    return 0;
}

/* ------------------------------------------------------------------------- */

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);

    const char *mode = NULL;
    int port = 0, rounds = 1000;
    size_t bytes = 64u * 1024u * 1024u, size = 64;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--mode=", 7) == 0) {
            mode = argv[i] + 7;
        } else if (strncmp(argv[i], "--port=", 7) == 0) {
            port = atoi(argv[i] + 7);
        } else if (strncmp(argv[i], "--bytes=", 8) == 0) {
            bytes = (size_t)strtoull(argv[i] + 8, NULL, 10);
        } else if (strncmp(argv[i], "--rounds=", 9) == 0) {
            rounds = atoi(argv[i] + 9);
        } else if (strncmp(argv[i], "--size=", 7) == 0) {
            size = (size_t)strtoull(argv[i] + 7, NULL, 10);
        } else {
            fprintf(stderr, "usage: load --mode=throughput|latency --port=N\n"
                            "            [--bytes=N] [--rounds=N] [--size=N]\n");
            return 2;
        }
    }
    if (mode == NULL || port <= 0) {
        fprintf(stderr, "usage: load --mode=throughput|latency --port=N\n");
        return 2;
    }
    if (strcmp(mode, "throughput") == 0) {
        return run_throughput(port, bytes);
    }
    if (strcmp(mode, "latency") == 0) {
        if (rounds < 100) {
            fprintf(stderr, "load: --rounds must be at least 100 for p99 to mean anything\n");
            return 2;
        }
        return run_latency(port, rounds, size);
    }
    fprintf(stderr, "load: unknown mode %s\n", mode);
    return 2;
}
