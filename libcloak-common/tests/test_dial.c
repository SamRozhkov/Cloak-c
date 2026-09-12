#define _POSIX_C_SOURCE 200809L
#include "cloak/net.h"
#include "test_framework.h"

#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct dial_capture {
    cloak_reactor_t *reactor;
    int fd;
    int calls;
};

static void on_dialed(int fd, void *userdata) {
    struct dial_capture *cap = userdata;
    cap->fd = fd;
    cap->calls++;
    cloak_reactor_stop(cap->reactor);
}

/* cloak_reactor_run() resets its stopped flag to 0 as soon as it is
 * entered (so a reactor can be restarted after a previous stop -- see
 * test_run_can_be_called_again_after_stop in test_reactor.c), which means
 * calling cloak_reactor_stop() *before* cloak_reactor_run() has no effect.
 * Tests that need to end a run() with nothing else registered must do so
 * via a timer callback running inside the loop instead. */
static void stop_reactor(cloak_reactor_t *r, void *userdata) {
    (void)userdata;
    cloak_reactor_stop(r);
}

/* Opens a listening socket on loopback and returns it, writing the bound
 * port to *out_port. Not registered with any reactor -- the tests below
 * only need something for connect() to succeed against. */
static int open_listener(int *out_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, 8) != 0) {
        close(fd);
        return -1;
    }
    socklen_t len = sizeof(sa);
    if (getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
        close(fd);
        return -1;
    }
    *out_port = ntohs(sa.sin_port);
    return fd;
}

static void test_resolve_loopback(void) {
    cloak_addr_t addr;
    char err[128] = {0};

    ASSERT_EQ_INT(0, cloak_net_resolve("127.0.0.1:8080", 0, &addr, err, sizeof(err)));
    ASSERT_TRUE(addr.len > 0);

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_net_resolve("localhost:8080", 0, &addr, err, sizeof(err)));

    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_net_resolve("no-port-here", 0, &addr, err, sizeof(err)));
    ASSERT_TRUE(err[0] != '\0');

    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_net_resolve("this-host-does-not-exist.invalid:80", 0, &addr,
                                        err, sizeof(err)));
    ASSERT_TRUE(err[0] != '\0');
}

static void test_dials_a_listening_port(void) {
    int port = 0;
    int listener = open_listener(&port);
    ASSERT_TRUE(listener >= 0);
    if (listener < 0) {
        return;
    }

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        close(listener);
        return;
    }

    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "127.0.0.1:%d", port);
    cloak_addr_t addr;
    char err[128] = {0};
    ASSERT_EQ_INT(0, cloak_net_resolve(addr_str, 0, &addr, err, sizeof(err)));

    struct dial_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;
    cap.fd = -2;

    cloak_dial_t d;
    ASSERT_EQ_INT(0, cloak_dial_start(&d, r, &addr, 5000, on_dialed, &cap));
    /* the contract: the callback never fires before start returns, even
     * when the connect completed immediately (which it does on loopback) */
    ASSERT_EQ_INT(0, cap.calls);

    cloak_reactor_run(r);

    ASSERT_EQ_INT(1, cap.calls);
    ASSERT_TRUE(cap.fd >= 0);

    if (cap.fd >= 0) {
        close(cap.fd);
    }
    close(listener);
    cloak_reactor_destroy(r);
}

static void test_dial_to_closed_port_fails(void) {
    /* Open a listener to get a port the kernel just handed out, then close
     * it -- connecting there gets a prompt ECONNREFUSED. */
    int port = 0;
    int listener = open_listener(&port);
    ASSERT_TRUE(listener >= 0);
    if (listener < 0) {
        return;
    }
    close(listener);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "127.0.0.1:%d", port);
    cloak_addr_t addr;
    char err[128] = {0};
    ASSERT_EQ_INT(0, cloak_net_resolve(addr_str, 0, &addr, err, sizeof(err)));

    struct dial_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;
    cap.fd = -2;

    cloak_dial_t d;
    ASSERT_EQ_INT(0, cloak_dial_start(&d, r, &addr, 5000, on_dialed, &cap));
    cloak_reactor_run(r);

    ASSERT_EQ_INT(1, cap.calls);
    ASSERT_EQ_INT(-1, cap.fd);

    cloak_reactor_destroy(r);
}

static void test_cancel_before_completion(void) {
    int port = 0;
    int listener = open_listener(&port);
    ASSERT_TRUE(listener >= 0);
    if (listener < 0) {
        return;
    }

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        close(listener);
        return;
    }

    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "127.0.0.1:%d", port);
    cloak_addr_t addr;
    char err[128] = {0};
    ASSERT_EQ_INT(0, cloak_net_resolve(addr_str, 0, &addr, err, sizeof(err)));

    struct dial_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.reactor = r;
    cap.fd = -2;

    cloak_dial_t d;
    ASSERT_EQ_INT(0, cloak_dial_start(&d, r, &addr, 5000, on_dialed, &cap));
    cloak_dial_cancel(&d);

    /* Nothing is left registered after cancel (fd removed, timer
     * cancelled), so run() would otherwise block in epoll_wait forever --
     * add a short timer purely to end the loop, per stop_reactor's
     * comment above. */
    ASSERT_TRUE(cloak_reactor_add_timer(r, 10, stop_reactor, NULL) != CLOAK_TIMER_INVALID);
    cloak_reactor_run(r);

    ASSERT_EQ_INT(0, cap.calls);

    close(listener);
    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_resolve_loopback();
    test_dials_a_listening_port();
    test_dial_to_closed_port_fails();
    test_cancel_before_completion();
TEST_MAIN_END()
