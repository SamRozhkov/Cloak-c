/* The thing behind the proxy: an echo server.
 *
 * WHY ECHO AND NOT A SINK. A sink measures one direction and hides the
 * other, and this port's two directions are not the same code -- the
 * client's and the server's relays are separate state machines, and an
 * asymmetry between them is exactly the kind of thing a benchmark is for.
 * Echoing makes every byte traverse both, so a number from this harness is
 * a round-trip number and says so.
 *
 * FORK PER CONNECTION, DELIBERATELY. A benchmark's upstream must not be
 * the bottleneck and must not be interesting. One process per connection
 * is the least clever thing that cannot serialise two proxied streams
 * behind each other; a single-threaded poll() loop here would have made
 * this file part of the measurement.
 *
 * It prints its listening port on stdout and then nothing, so a driver
 * can bind :0 and read the port back rather than guessing a free one. */

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static void serve(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    /* 256 KiB: large enough that the read syscall is not the cost being
     * measured, small enough to stay in cache. */
    static char buf[262144];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n == 0) {
            return;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = send(fd, buf + off, (size_t)(n - off), MSG_NOSIGNAL);
            if (w <= 0) {
                if (w < 0 && errno == EINTR) {
                    continue;
                }
                return;
            }
            off += w;
        }
    }
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN); /* no zombies, no wait() in the accept loop */

    int ln = socket(AF_INET, SOCK_STREAM, 0);
    if (ln < 0) {
        perror("socket");
        return 1;
    }
    int one = 1;
    setsockopt(ln, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0; /* the kernel picks; we print what it picked */
    if (bind(ln, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(ln, 128) != 0) {
        perror("bind/listen");
        return 1;
    }
    socklen_t sl = sizeof(sa);
    if (getsockname(ln, (struct sockaddr *)&sa, &sl) != 0) {
        perror("getsockname");
        return 1;
    }
    printf("%d\n", (int)ntohs(sa.sin_port));
    fflush(stdout);

    for (;;) {
        int c = accept(ln, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 1;
        }
        pid_t p = fork();
        if (p == 0) {
            close(ln);
            serve(c);
            _exit(0);
        }
        close(c);
    }
}
